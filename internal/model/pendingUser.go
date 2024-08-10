package model

import (
	"time"
)

type PendingUser struct {
	Email         string    `db:"email"`
	PasswordHash  string    `db:"password_hash"`
	Code          int       `db:"code"`
	CodeExpiresAt time.Time `db:"code_expires_at"`
}
