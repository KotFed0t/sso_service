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
	CheckUserExists(ctx context.Context, email string) (bool, error)
	UpsertPendingUser(ctx context.Context, email string, passwordHash string, code int, codeExpiresAt time.Time) error
	GetPendingUser(ctx context.Context, email string) (user model.PendingUser, err error)
	DeletePendingUser(ctx context.Context, email string) error
	InsertRefreshToken(ctx context.Context, userUuid, refreshToken, clientIp string) error
	CheckRefreshTokenExistence(ctx context.Context, userUuid, refreshToken, clientIp string) (bool, error)
	UpdateRefreshToken(ctx context.Context, userUuid, oldRefreshToken, newRefreshToken string) error
	UpsertPasswordResetToken(ctx context.Context, userUuid string, token string, expiresAt time.Time) error
	CheckResetPasswordTokenAndUuidExistence(ctx context.Context, uuid, token string) (bool, error)
	UpdateUserPassword(ctx context.Context, uuid, passwordHash string) error
	DeleteUuidFromPasswordReset(ctx context.Context, uuid string) error
	DeleteRefreshToken(ctx context.Context, refreshToken string) error
}
