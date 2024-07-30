package oauthService

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/yandex"
	"io"
	"net/http"
	"sso_service/config"
)

type OAuthService struct {
	cfg          *config.Config
	googleConfig *oauth2.Config
	yandexConfig *oauth2.Config
}

func NewOAuthService(cfg *config.Config) *OAuthService {
	var googleConfig = &oauth2.Config{
		RedirectURL:  cfg.Google.CallbackURL,
		ClientID:     cfg.Google.ClientID,
		ClientSecret: cfg.Google.ClientSecret,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	yandexConfig := &oauth2.Config{
		RedirectURL:  cfg.Yandex.CallbackURL,
		ClientID:     cfg.Yandex.ClientID,
		ClientSecret: cfg.Yandex.ClientSecret,
		Scopes:       []string{"login:email"},
		Endpoint:     yandex.Endpoint,
	}
	return &OAuthService{cfg: cfg, googleConfig: googleConfig, yandexConfig: yandexConfig}
}

func (s *OAuthService) GetRedirectURL(ctx *gin.Context, authProvider string) (string, error) {
	state := s.generateStateOauthCookie(ctx)
	switch authProvider {
	case "yandex":
		return s.yandexConfig.AuthCodeURL(state), nil
	case "google":
		return s.googleConfig.AuthCodeURL(state), nil
	default:
		return "", fmt.Errorf("invalid auth provider: %s", authProvider)

	}
}

func (s *OAuthService) generateStateOauthCookie(ctx *gin.Context) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	ctx.SetCookie("oauthstate", state, 24*60*60, "/", "localhost", false, true)
	return state
}

func (s *OAuthService) OauthProviderCallback(ctx *gin.Context, authProvider string) (string, error) {
	oauthState, err := ctx.Cookie("oauthstate")
	if err != nil {
		return "", fmt.Errorf("failed on get oauthstate cookie: %w", err)
	}

	if ctx.Query("state") != oauthState {
		return "", errors.New("invalid oauth google state")
	}

	switch authProvider {
	case "yandex":
		data, err := s.getUserData(ctx.Query("code"), s.yandexConfig, s.cfg.Yandex.UserInfoUrl)
		if err != nil {
			return "", fmt.Errorf("err getUserData from Yandex: %w", err)
		}

		type YandexResponse struct {
			Email string `json:"default_email"`
		}

		var yandexResponse YandexResponse
		err = json.Unmarshal(data, &yandexResponse)
		if err != nil {
			return "", fmt.Errorf("err while unmarshall yandexResponse: %w", err)
		}
		return yandexResponse.Email, nil
	case "google":
		data, err := s.getUserData(ctx.Query("code"), s.googleConfig, s.cfg.Google.UserInfoUrl)
		if err != nil {
			return "", fmt.Errorf("err getUserData from Google: %w", err)
		}

		type GoogleResponse struct {
			Email string `json:"email"`
		}

		var googleResponse GoogleResponse
		err = json.Unmarshal(data, &googleResponse)
		if err != nil {
			return "", fmt.Errorf("err while unmarshall googleResponse: %w", err)
		}
		return googleResponse.Email, nil
	default:
		return "", fmt.Errorf("invalid auth provider: %s", authProvider)
	}
}

func (s *OAuthService) getUserData(code string, providerConfig *oauth2.Config, userInfoUrl string) ([]byte, error) {
	token, err := providerConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %w", err)
	}
	response, err := http.Get(userInfoUrl + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %w", err)
	}
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %w", err)
	}
	return contents, nil
}
