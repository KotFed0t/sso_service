package serviceInterface

import (
	"context"
)

type IOAuthService interface {
	GetRedirectURLAndState(ctx context.Context, authProvider string) (url, state string, err error)
	HandleCallbackAndLoginUser(ctx context.Context, authProviderName, callbackCode, clientIp string) (accessToken, refreshToken string, err error)
}
