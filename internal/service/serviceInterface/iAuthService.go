package serviceInterface

import "context"

type AuthService interface {
	FirstRegistrationPhase(ctx context.Context, email, password string) error
	ConfirmEmailAndFinishRegistration(ctx context.Context, email string, code int, clientIp string) (accessToken, refreshToken string, err error)
	LoginUser(ctx context.Context, email, password, clientIp string) (accessToken, refreshToken string, err error)
	RefreshTokens(ctx context.Context, refreshToken, clientIp string) (newAccessToken, newRefreshToken string, err error)
}
