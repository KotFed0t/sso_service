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

func (r *PostgresRepo) CheckUserExists(ctx context.Context, email string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)`
	err := r.db.QueryRowxContext(ctx, query, email).Scan(&exists)
	return exists, err
}

func (r *PostgresRepo) UpsertPendingUser(
	ctx context.Context,
	email string,
	passwordHash string,
	code int,
	codeExpiresAt time.Time,
) error {
	query := `
	INSERT INTO pending_users 
    (email, password_hash, code, code_expires_at) 
	VALUES ($1, $2, $3, $4) 
	ON CONFLICT(email) DO UPDATE 
	    set email=excluded.email,
	    	password_hash=excluded.password_hash,
	    	code=excluded.code,
	    	code_expires_at=excluded.code_expires_at
	`
	_, err := r.db.ExecContext(ctx, query, email, passwordHash, code, codeExpiresAt)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepo) GetPendingUser(ctx context.Context, email string) (pendingUser model.PendingUser, err error) {
	query := `SELECT email, password_hash, code, code_expires_at FROM pending_users WHERE email = $1;`
	err = r.db.GetContext(ctx, &pendingUser, query, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.PendingUser{}, ErrNoRows
		}
		return model.PendingUser{}, err
	}
	return pendingUser, nil
}

func (r *PostgresRepo) DeletePendingUser(ctx context.Context, email string) error {
	query := `DELETE FROM pending_users WHERE email = $1;`
	_, err := r.db.ExecContext(ctx, query, email)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepo) InsertRefreshToken(ctx context.Context, userUuid, refreshToken, clientIp string) error {
	query := `INSERT INTO refresh_tokens (user_uuid, refresh_token, ip_address) VALUES ($1, $2, $3);`
	_, err := r.db.ExecContext(ctx, query, userUuid, refreshToken, clientIp)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepo) CheckRefreshTokenExistence(ctx context.Context, userUuid, refreshToken, clientIp string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1 FROM refresh_tokens 
		    	WHERE user_uuid = $1 
		           AND refresh_token = $2
    			   AND ip_address = $3
		)`
	err := r.db.QueryRowxContext(ctx, query, userUuid, refreshToken, clientIp).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (r *PostgresRepo) UpdateRefreshToken(ctx context.Context, userUuid, oldRefreshToken, newRefreshToken string) error {
	query := `
		UPDATE refresh_tokens 
		set 
		    refresh_token = $1,
		    created_at = now()
		where user_uuid = $2
			and refresh_token = $3
		`
	_, err := r.db.ExecContext(ctx, query, newRefreshToken, userUuid, oldRefreshToken)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepo) UpsertPasswordResetToken(
	ctx context.Context,
	userUuid string,
	token string,
	expiresAt time.Time,
) error {
	query := `
		INSERT INTO password_reset_tokens (user_uuid, token, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_uuid)
		DO UPDATE 
		    SET user_uuid = excluded.user_uuid,
    			token = excluded.token,
    			expires_at = excluded.expires_at;
	`
	_, err := r.db.ExecContext(ctx, query, userUuid, token, expiresAt)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepo) CheckResetPasswordTokenAndUuidExistence(ctx context.Context, uuid, token string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1 FROM password_reset_tokens 
		         WHERE user_uuid = $1 
		           and token = $2 
		           and expires_at > now()
		);
	`
	err := r.db.QueryRowxContext(ctx, query, uuid, token).Scan(&exists)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return exists, nil
}

func (r *PostgresRepo) UpdateUserPassword(ctx context.Context, uuid, passwordHash string) error {
	query := `UPDATE users SET password_hash = $1 WHERE uuid = $2;`
	_, err := r.db.ExecContext(ctx, query, passwordHash, uuid)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepo) DeleteUuidFromPasswordReset(ctx context.Context, uuid string) error {
	query := `DELETE FROM password_reset_tokens WHERE user_uuid = $1;`
	_, err := r.db.ExecContext(ctx, query, uuid)
	if err != nil {
		return err
	}
	return nil
}

func (r *PostgresRepo) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	query := `DELETE FROM refresh_tokens WHERE refresh_token = $1;`
	_, err := r.db.ExecContext(ctx, query, refreshToken)
	if err != nil {
		return err
	}
	return nil
}
