package oauthService

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/yandex"
	"slices"
	"sso_service/config"
	"sso_service/internal/model"
	"sso_service/internal/repository"
	"sso_service/internal/utils"
	"time"
)

type OAuthService struct {
	cfg          *config.Config
	repo         repository.IRepository
	googleConfig *oauth2.Config
	yandexConfig *oauth2.Config
}

func NewOAuthService(cfg *config.Config, repo repository.IRepository) *OAuthService {
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
	return &OAuthService{cfg: cfg, repo: repo, googleConfig: googleConfig, yandexConfig: yandexConfig}
}

func (s *OAuthService) GetRedirectURLAndState(ctx context.Context, authProvider string) (url, state string, err error) {
	state = s.generateOauthState()
	switch authProvider {
	case "yandex":
		return s.yandexConfig.AuthCodeURL(state), state, nil
	case "google":
		return s.googleConfig.AuthCodeURL(state), state, nil
	default:
		return "", "", fmt.Errorf("invalid auth provider: %s", authProvider)
	}
}

func (s *OAuthService) generateOauthState() string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	return state
}

// getUserEmailFromOauthProvider handle oauth provider callback and get user email from response.
func (s *OAuthService) getUserEmailFromOauthProvider(ctx context.Context, authProviderName, callbackCode string) (email string, err error) {
	switch authProviderName {
	case "yandex":
		data, err := s.getUserData(ctx, callbackCode, s.yandexConfig, s.cfg.Yandex.UserInfoUrl)
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
		data, err := s.getUserData(ctx, callbackCode, s.googleConfig, s.cfg.Google.UserInfoUrl)
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
		return "", fmt.Errorf("invalid auth provider: %s", authProviderName)
	}
}

func (s *OAuthService) getUserData(ctx context.Context, code string, providerConfig *oauth2.Config, userInfoUrl string) ([]byte, error) {
	token, err := providerConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	client := resty.New()
	response, err := client.R().
		SetContext(ctx).
		Get(userInfoUrl + token.AccessToken)

	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %w", err)
	}
	return response.Body(), nil
}

func (s *OAuthService) HandleCallbackAndLoginUser(
	ctx context.Context,
	authProviderName, callbackCode, clientIp string,
) (accessToken, refreshToken string, err error) {
	email, err := s.getUserEmailFromOauthProvider(ctx, authProviderName, callbackCode)
	if err != nil {
		return "", "", fmt.Errorf("failed on getUserEmailFromOauthProvider: %w", err)
	}

	user, err := s.getOrCreateUser(ctx, email, authProviderName)
	if err != nil {
		return "", "", fmt.Errorf("failed on getOrCreateUser: %w", err)
	}

	accessToken, refreshToken, err = s.generateAccessAndRefreshTokens(user.Uuid)
	if err != nil {
		return "", "", fmt.Errorf("failed on generateAccessAndRefreshTokens: %w", err)
	}

	err = s.saveRefreshTokenToDb(ctx, refreshToken, user.Uuid, clientIp)
	if err != nil {
		return "", "", fmt.Errorf("failed on saveRefreshTokenToDb: %w", err)
	}

	return accessToken, refreshToken, nil
}

func (s *OAuthService) generateAccessAndRefreshTokens(userUuid string) (accessToken, refreshToken string, err error) {
	claims := jwt.MapClaims{
		"sub": userUuid,
		"exp": time.Now().Add(s.cfg.Jwt.AccessTokenTtl).Unix(),
	}
	accessToken, err = utils.GenerateJWT(s.cfg.Jwt.SecretKey, claims)
	if err != nil {
		return "", "", fmt.Errorf("failed on GenerateJWT accessToken: %w", err)
	}

	claims = jwt.MapClaims{
		"sub": userUuid,
		"exp": time.Now().Add(s.cfg.Jwt.RefreshTokenTtl).Unix(),
	}
	refreshToken, err = utils.GenerateJWT(s.cfg.Jwt.SecretKey, claims)
	if err != nil {
		return "", "", fmt.Errorf("failed on GenerateJWT accessToken: %w", err)
	}

	return accessToken, refreshToken, nil
}

// getOrCreateUser создает пользователя и связку с auth provider если не было. Возвращает модель пользователя.
func (s *OAuthService) getOrCreateUser(ctx context.Context, email, authProviderName string) (user model.User, err error) {
	user, err = s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNoRows) {
			// user does not exist - create user
			userUuid, err := s.repo.CreateUserWithoutPassword(ctx, email)
			if err != nil {
				return model.User{}, fmt.Errorf("failed on CreateUserWithoutPassword: %w", err)
			}
			err = s.repo.AddUserAuthProvider(ctx, userUuid, authProviderName)
			if err != nil {
				return model.User{}, fmt.Errorf("failed on CreateUserWithoutPassword: %w", err)
			}
			user.Uuid = userUuid
			user.Email = email
			return user, nil
		}

		return model.User{}, fmt.Errorf("failed on GetUserByEmail: %w", err)
	}

	// user exists
	providers, err := s.repo.GetUserAuthProviders(ctx, user.Uuid)
	if err != nil {
		return model.User{}, fmt.Errorf("failed on GetUserAuthProviders: %w", err)
	}

	if !slices.Contains(providers, authProviderName) {
		err := s.repo.AddUserAuthProvider(ctx, user.Uuid, authProviderName)
		if err != nil {
			return model.User{}, fmt.Errorf("failed on AddUserAuthProvider: %w", err)
		}
	}
	return user, nil
}

func (s *OAuthService) saveRefreshTokenToDb(ctx context.Context, refreshToken, userUuid, clientIp string) error {
	exist, err := s.repo.CheckExistenceUserUuidInRefreshTokens(ctx, userUuid)
	if err != nil {
		return fmt.Errorf("failed on CheckExistenceUserUuidInRefreshTokens: %w", err)
	}

	if exist {
		err = s.repo.UpdateRefreshTokens(ctx, userUuid, refreshToken, clientIp)
		if err != nil {
			return fmt.Errorf("failed on CheckExistenceUserUuidInRefreshTokens: %w", err)
		}
		return nil
	}

	err = s.repo.InsertIntoRefreshTokens(ctx, userUuid, refreshToken, clientIp)
	if err != nil {
		return fmt.Errorf("failed on InsertIntoRefreshTokens: %w", err)
	}

	return nil
}
