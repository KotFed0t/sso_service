package apiInterface

import (
	"context"
	"golang.org/x/oauth2"
)

type IOAuthClient interface {
	Exchange(ctx context.Context, code string, providerConfig *oauth2.Config) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, userInfoUrl, accessToken string) ([]byte, error)
}
