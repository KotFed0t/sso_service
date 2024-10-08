package service

import "errors"

var (
	ErrUserAlreadyExists              = errors.New("user already exists")
	ErrWrongCodeOrExpired             = errors.New("code is wrong or expired")
	ErrWrongEmailOrPassword           = errors.New("email or password is wrong")
	ErrInvalidRefreshToken            = errors.New("invalid refresh token")
	ErrResetPasswordNotValidOrExpired = errors.New("uuid or token is not valid or expired in reset_password_token")
)
