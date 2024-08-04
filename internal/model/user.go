package model

import "database/sql"

type User struct {
	Uuid         string         `db:"uuid"`
	Email        string         `db:"email"`
	PasswordHash sql.NullString `db:"password_hash"`
}
