package authService

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"math/rand"
	"sso_service/config"
	"sso_service/data/queue/kafka/notificationProducer"
	"sso_service/internal/model"
	"sso_service/internal/repository"
	"sso_service/internal/service"
	"sso_service/internal/utils"
	"strconv"
	"time"
)

type AuthService struct {
	cfg           *config.Config
	repo          repository.IRepository
	notifProducer notificationProducer.INotificationProducer
}

func New(
	cfg *config.Config,
	repo repository.IRepository,
	notifProducer notificationProducer.INotificationProducer,
) *AuthService {
	return &AuthService{cfg: cfg, repo: repo, notifProducer: notifProducer}
}

func (s *AuthService) FirstRegistrationPhase(ctx context.Context, email, password string) error {
	exists, err := s.repo.CheckUserExists(ctx, email)
	if err != nil {
		return fmt.Errorf("failed on CheckUserExists: %w", err)
	}

	if exists {
		return service.ErrUserAlreadyExists
	}

	code := s.genCode()
	codeExpiresAt := time.Now().Add(15 * time.Minute)
	passwordHash, err := s.hashPassword(password)
	if err != nil {
		return fmt.Errorf("failed on hashPassword: %w", err)
	}
	err = s.repo.UpsertPendingUser(ctx, email, passwordHash, code, codeExpiresAt)
	if err != nil {
		return fmt.Errorf("failed on UpsertPendingUser: %w", err)
	}

	go s.notifProducer.Send(context.Background(), email, model.NotificationMessage{
		Email:        email,
		Subject:      s.cfg.SubjectEmailConfirmation,
		TemplateName: s.cfg.TemplateNameEmailConfirmation,
		Parameters: map[string]string{
			"Code": strconv.Itoa(code),
		},
	})

	return nil
}

func (s *AuthService) genCode() int {
	return rand.Intn(999999-100000+1) + 100000
}

func (s *AuthService) hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func (s *AuthService) checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false
	}
	return true
}

func (s *AuthService) ConfirmEmailAndFinishRegistration(
	ctx context.Context,
	email string,
	code int,
	clientIp string,
) (accessToken, refreshToken string, err error) {
	pendingUser, err := s.repo.GetPendingUser(ctx, email)
	if err != nil {
		return "", "", fmt.Errorf("failed on GetPendingUser: %w", err)
	}

	if pendingUser.CodeExpiresAt.Before(time.Now()) {
		return "", "", service.ErrWrongCodeOrExpired
	}

	if code != pendingUser.Code {
		return "", "", service.ErrWrongCodeOrExpired
	}

	userUuid, err := s.repo.CreateUserWithPassword(ctx, email, pendingUser.PasswordHash)
	if err != nil {
		return "", "", fmt.Errorf("failed on CreateUserWithPassword: %w", err)
	}

	err = s.repo.DeletePendingUser(ctx, email)
	if err != nil {
		return "", "", fmt.Errorf("failed on DeletePendingUser: %w", err)
	}

	accessToken, refreshToken, err = utils.GenerateAccessAndRefreshTokens(
		userUuid,
		s.cfg.Jwt.AccessTokenTtl,
		s.cfg.Jwt.RefreshTokenTtl,
		s.cfg.Jwt.SecretKey,
	)
	if err != nil {
		return "", "", fmt.Errorf("failed on GenerateAccessAndRefreshTokens: %w", err)
	}

	err = s.repo.InsertRefreshToken(ctx, userUuid, refreshToken, clientIp)
	if err != nil {
		return "", "", fmt.Errorf("failed on InsertRefreshToken: %w", err)
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) LoginUser(ctx context.Context, email, password, clientIp string) (accessToken, refreshToken string, err error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNoRows) {
			return "", "", service.ErrWrongEmailOrPassword
		}
		return "", "", fmt.Errorf("failed on GetUserByEmail: %w", err)
	}

	if !user.PasswordHash.Valid {
		return "", "", service.ErrWrongEmailOrPassword
	}

	if !s.checkPasswordHash(password, user.PasswordHash.String) {
		return "", "", service.ErrWrongEmailOrPassword
	}

	accessToken, refreshToken, err = utils.GenerateAccessAndRefreshTokens(
		user.Uuid,
		s.cfg.Jwt.AccessTokenTtl,
		s.cfg.Jwt.RefreshTokenTtl,
		s.cfg.Jwt.SecretKey,
	)
	if err != nil {
		return "", "", fmt.Errorf("failed on GenerateAccessAndRefreshTokens: %w", err)
	}

	err = s.repo.InsertRefreshToken(ctx, user.Uuid, refreshToken, clientIp)
	if err != nil {
		return "", "", fmt.Errorf("failed on InsertRefreshToken: %w", err)
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken, clientIp string) (newAccessToken, newRefreshToken string, err error) {
	userUuid, err := utils.ValidateTokenAndGetUserUuid(refreshToken, s.cfg.Jwt.SecretKey)
	if err != nil {
		return "", "", service.ErrInvalidRefreshToken
	}

	exists, err := s.repo.CheckRefreshTokenExistence(ctx, userUuid, refreshToken, clientIp)
	if err != nil {
		return "", "", err
	}

	if !exists {
		return "", "", service.ErrInvalidRefreshToken
	}

	newAccessToken, newRefreshToken, err = utils.GenerateAccessAndRefreshTokens(
		userUuid,
		s.cfg.Jwt.AccessTokenTtl,
		s.cfg.Jwt.RefreshTokenTtl,
		s.cfg.Jwt.SecretKey,
	)
	if err != nil {
		return "", "", fmt.Errorf("failed on GenerateAccessAndRefreshTokens: %w", err)
	}

	err = s.repo.UpdateRefreshToken(ctx, userUuid, refreshToken, newRefreshToken)
	if err != nil {
		return "", "", fmt.Errorf("failed on UpdateRefreshToken: %w", err)
	}

	return newAccessToken, newRefreshToken, nil
}

func (s *AuthService) SendResetPasswordLink(ctx context.Context, email string) error {
	// найти юзера по email, если нет - вернуть nil а не ошибку, чтобы не раскрывать суть
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNoRows) {
			// если email нет - не раскрываем инфо об этом клиенту
			return nil
		}
		return fmt.Errorf("failed on GetUserByEmail: %w", err)
	}

	token := s.getRandomTokenString(64)
	err = s.repo.UpsertPasswordResetToken(ctx, user.Uuid, token, time.Now().Add(15*time.Minute))
	if err != nil {
		return fmt.Errorf("failed on UpsertPasswordResetToken: %w", err)
	}

	resetPasswordUrl := fmt.Sprintf("%s?token=%s&uuid=%s", s.cfg.ResetPasswordUrl, token, user.Uuid)
	slog.Info("", "resetPasswordUrl", resetPasswordUrl)

	go s.notifProducer.Send(context.Background(), email, model.NotificationMessage{
		Email:        email,
		Subject:      s.cfg.SubjectResetPassword,
		TemplateName: s.cfg.TemplateNameResetPassword,
		Parameters: map[string]string{
			"Link": resetPasswordUrl,
		},
	})

	return nil
}

func (s *AuthService) getRandomTokenString(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)

}

func (s *AuthService) ResetPassword(ctx context.Context, uuid, token, password string) error {
	exists, err := s.repo.CheckResetPasswordTokenAndUuidExistence(ctx, uuid, token)
	if err != nil {
		return fmt.Errorf("failed on CheckResetPasswordTokenAndUuidExistence: %w", err)
	}

	if !exists {
		return service.ErrResetPasswordNotValidOrExpired
	}

	passwordHash, err := s.hashPassword(password)
	if err != nil {
		return fmt.Errorf("failed on hashPassword: %w", err)
	}

	err = s.repo.UpdateUserPassword(ctx, uuid, passwordHash)
	if err != nil {
		return fmt.Errorf("failed on UpdateUserPassword: %w", err)
	}

	err = s.repo.DeleteUuidFromPasswordReset(ctx, uuid)
	if err != nil {
		return fmt.Errorf("failed on UpdateUserPassword: %w", err)
	}

	return nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	err := s.repo.DeleteRefreshToken(ctx, refreshToken)
	if err != nil {
		return fmt.Errorf("failed on DeleteRefreshToken: %w", err)
	}
	return nil
}
