package serviceInterface

import "context"

type AuthService interface {
	FirstRegistrationPhase(ctx context.Context, email, password string) error
}
