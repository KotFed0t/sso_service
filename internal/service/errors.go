package service

import "errors"

var (
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrWrongCodeOrExpired = errors.New("code is wrong or expired")
)
