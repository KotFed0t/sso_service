package authService

import (
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"sso_service/config"
	"sso_service/internal/repository"
	"sso_service/internal/service"
	"sso_service/internal/utils"
	"time"
)

type AuthService struct {
	cfg  *config.Config
	repo repository.IRepository
}

func New(cfg *config.Config, repo repository.IRepository) *AuthService {
	return &AuthService{cfg: cfg, repo: repo}
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

	return nil
	// TODO код отправляем на email
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

func (s *AuthService) checkPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
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

	err = s.repo.UpsertRefreshTokens(ctx, userUuid, refreshToken, clientIp)
	if err != nil {
		return "", "", fmt.Errorf("failed on UpsertRefreshTokens: %w", err)
	}

	return accessToken, refreshToken, nil
}
