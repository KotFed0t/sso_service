package repository

import (
	"context"
	"database/sql"
	"errors"
	"github.com/jmoiron/sqlx"
	"sso_service/internal/model"
	"time"
)

type PostgresRepo struct {
	db *sqlx.DB
}

func NewPostgresRepo(db *sqlx.DB) *PostgresRepo {
	return &PostgresRepo{db}
}

func (r *PostgresRepo) GetUserByEmail(ctx context.Context, email string) (model.User, error) {
	var user model.User
	query := `SELECT uuid, email, password_hash FROM users WHERE email = $1`
	err := r.db.GetContext(ctx, &user, query, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.User{}, ErrNoRows
		}
		return model.User{}, err
	}
	return user, nil
}

func (r *PostgresRepo) GetUserAuthProviders(ctx context.Context, userUuid string) (authProviders []string, err error) {
	query := `SELECT provider_name FROM auth_providers WHERE user_uuid = $1;`
	err = r.db.SelectContext(ctx, &authProviders, query, userUuid)
	if err != nil {
		return nil, err
	}
	return authProviders, nil
}

func (r *PostgresRepo) CreateUserWithoutPassword(ctx context.Context, email string) (userUuid string, err error) {
	query := `INSERT INTO users (email) VALUES ($1) RETURNING uuid;`
	err = r.db.QueryRowxContext(ctx, query, email).Scan(&userUuid)
	if err != nil {
		return "", err
	}
	return userUuid, nil
}

func (r *PostgresRepo) CreateUserWithPassword(ctx context.Context, email, passwordHash string) (userUuid string, err error) {
	query := `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING uuid;`
	err = r.db.QueryRowxContext(ctx, query, email, passwordHash).Scan(&userUuid)
	if err != nil {
		return "", err
	}
	return userUuid, nil
}

func (r *PostgresRepo) AddUserAuthProvider(ctx context.Context, userUuid, providerName string) error {
	query := `INSERT INTO auth_providers (user_uuid, provider_name) VALUES ($1, $2);`
	_, err := r.db.ExecContext(ctx, query, userUuid, providerName)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepo) CheckExistenceUserUuidInRefreshTokens(ctx context.Context, userUuid string) (bool, error) {
	query := `SELECT user_uuid FROM refresh_tokens WHERE user_uuid = $1;`
	var res string
	err := r.db.GetContext(ctx, &res, query, userUuid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *PostgresRepo) InsertIntoRefreshTokens(ctx context.Context, userUuid, refreshToken, clientIp string) error {
	query := `INSERT INTO refresh_tokens (user_uuid, refresh_tokens, ip_addresses) VALUES ($1, ARRAY[$2], ARRAY[$3]);`
	_, err := r.db.ExecContext(ctx, query, userUuid, refreshToken, clientIp)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepo) UpdateRefreshTokens(ctx context.Context, userUuid, refreshToken, clientIp string) error {
	query := `
		UPDATE refresh_tokens 
		SET refresh_tokens = array_append(refresh_tokens, $1),
		    ip_addresses = array_append(ip_addresses, $2)
		WHERE user_uuid = $3;`
	_, err := r.db.ExecContext(ctx, query, refreshToken, clientIp, userUuid)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepo) CheckUserExists(ctx context.Context, email string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)`
	err := r.db.QueryRowContext(ctx, query, email).Scan(&exists)
	return exists, err
}

func (r *PostgresRepo) SavePendingUser(
	ctx context.Context,
	email string,
	passwordHash string,
	code int,
	codeExpiresAt time.Time,
) error {
	query := `INSERT INTO pending_users (email, password_hash, code, code_expires_at) VALUES ($1, $2, $3, $4)`
	_, err := r.db.ExecContext(ctx, query, email, passwordHash, code, codeExpiresAt)
	if err != nil {
		return err
	}
	return nil
}
