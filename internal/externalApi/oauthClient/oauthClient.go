package oauthClient

import (
	"context"
	"github.com/go-resty/resty/v2"
	"golang.org/x/oauth2"
)

type OauthClient struct{}

func (c *OauthClient) Exchange(ctx context.Context, code string, providerConfig *oauth2.Config) (*oauth2.Token, error) {
	token, err := providerConfig.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (c *OauthClient) GetUserInfo(ctx context.Context, userInfoUrl, accessToken string) ([]byte, error) {
	client := resty.New()
	response, err := client.R().
		SetContext(ctx).
		Get(userInfoUrl + accessToken)

	if err != nil {
		return nil, err
	}
	return response.Body(), nil
}
