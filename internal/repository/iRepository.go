package repository

import (
	"context"
	"sso_service/internal/model"
	"time"
)

type IRepository interface {
	GetUserByEmail(ctx context.Context, email string) (model.User, error)
	GetUserAuthProviders(ctx context.Context, userUuid string) (authProviders []string, err error)
	CreateUserWithoutPassword(ctx context.Context, email string) (userUuid string, err error)
	CreateUserWithPassword(ctx context.Context, email, passwordHash string) (userUuid string, err error)
	AddUserAuthProvider(ctx context.Context, userUuid, providerName string) error
	CheckExistenceUserUuidInRefreshTokens(ctx context.Context, userUuid string) (bool, error)
	InsertIntoRefreshTokens(ctx context.Context, userUuid, refreshToken, clientIp string) error
	CheckUserExists(ctx context.Context, email string) (bool, error)
	UpsertPendingUser(ctx context.Context, email string, passwordHash string, code int, codeExpiresAt time.Time) error
	GetPendingUser(ctx context.Context, email string) (user model.PendingUser, err error)
	DeletePendingUser(ctx context.Context, email string) error
	UpsertRefreshTokens(ctx context.Context, userUuid, refreshToken, clientIp string) error
	CheckRefreshTokenExistence(ctx context.Context, userUuid, refreshToken, clientIp string) (bool, error)
	UpdateRefreshToken(ctx context.Context, userUuid, oldRefreshToken, newRefreshToken string) error
	UpsertPasswordResetToken(ctx context.Context, userUuid string, tokenHash string, expiresAt time.Time) error
}
