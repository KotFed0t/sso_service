package serviceInterface

import "context"

type AuthService interface {
	FirstRegistrationPhase(ctx context.Context, email, password string) error
	ConfirmEmailAndFinishRegistration(ctx context.Context, email string, code int, clientIp string) (accessToken, refreshToken string, err error)
}
