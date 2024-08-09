package authService

import (
	"context"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"sso_service/config"
	"sso_service/internal/repository"
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
		return fmt.Errorf("failed on CheckUserExists: %s", err)
	}

	if exists {
		return ErrUserAlreadyExists
	}

	code := s.genCode()
	codeExpiresAt := time.Now().Add(15 * time.Minute)
	passwordHash, err := s.hashPassword(password)
	if err != nil {
		return fmt.Errorf("failed on hashPassword: %s", err)
	}
	err = s.repo.SavePendingUser(ctx, email, passwordHash, code, codeExpiresAt)
	if err != nil {
		return fmt.Errorf("failed on SavePendingUser: %s", err)
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
