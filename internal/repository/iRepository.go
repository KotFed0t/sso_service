package repository

import (
	"context"
	"sso_service/internal/model"
)

type IRepository interface {
	GetUserByEmail(ctx context.Context, email string) (model.User, error)
	GetUserAuthProviders(ctx context.Context, userUuid string) (authProviders []string, err error)
	CreateUserWithoutPassword(ctx context.Context, email string) (userUuid string, err error)
	CreateUserWithPassword(ctx context.Context, email, passwordHash string) (userUuid string, err error)
	AddUserAuthProvider(ctx context.Context, userUuid, providerName string) error
	CheckExistenceUserUuidInRefreshTokens(ctx context.Context, userUuid string) (bool, error)
	InsertIntoRefreshTokens(ctx context.Context, userUuid, refreshToken, clientIp string) error
	UpdateRefreshTokens(ctx context.Context, userUuid, refreshToken, clientIp string) error
}
