package oauthService

import (
	"context"
	"database/sql"
	"errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"sso_service/config"
	"sso_service/internal/model"
	"sso_service/internal/repository"
	"sso_service/mocks"
	"testing"
)

func TestGetRedirectURLAndState(t *testing.T) {
	tests := []struct {
		name         string
		authProvider string
		expectedUrl  string
		err          error
	}{
		{
			name:         "positive google",
			authProvider: "google",
			err:          nil,
		},
		{
			name:         "positive yandex",
			authProvider: "yandex",
			err:          nil,
		},
		{
			name:         "negative not existence provider",
			authProvider: "vk",
			err:          errors.New("invalid auth provider: vk"),
		},
	}

	cfg := config.MustLoadForTests()
	repo := mocks.NewIRepository(t)
	oauthClient := mocks.NewIOAuthClient(t)
	oauthSrv := New(cfg, repo, oauthClient)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			url, state, err := oauthSrv.GetRedirectURLAndState(ctx, test.authProvider)

			assert.Equal(t, test.err, err)
			if err == nil {
				assert.NotEmpty(t, url)
				assert.NotEmpty(t, state)
			}
		})
	}
}

func TestGetUserEmailFromOauthProvider(t *testing.T) {
	cfg := config.MustLoadForTests()
	repo := mocks.NewIRepository(t)
	oauthClient := mocks.NewIOAuthClient(t)
	oauthSrv := New(cfg, repo, oauthClient)

	type oauthClientFields struct {
		providerCfg *oauth2.Config
		userInfoUrl string
		token       *oauth2.Token
		body        []byte
		exchangeErr error
		getInfoErr  error
	}

	tests := []struct {
		name              string
		authProvider      string
		callbackCode      string
		expectedEmail     string
		oauthClientFields oauthClientFields
		hasErr            bool
		detailErr         error
	}{
		{
			name:          "positive yandex",
			authProvider:  "yandex",
			hasErr:        false,
			callbackCode:  "yandexCallbackCode1",
			expectedEmail: "test1@yandex.ru",
			oauthClientFields: oauthClientFields{
				providerCfg: oauthSrv.yandexConfig,
				userInfoUrl: cfg.Yandex.UserInfoUrl,
				token:       &oauth2.Token{AccessToken: "accessTokenFromExchange1"},
				body:        []byte(`{"default_email":"test1@yandex.ru","other_field":"someInfo"}`),
				exchangeErr: nil,
				getInfoErr:  nil,
			},
		},
		{
			name:          "positive google",
			authProvider:  "google",
			hasErr:        false,
			callbackCode:  "googleCallbackCode1",
			expectedEmail: "test2@gmail.com",
			oauthClientFields: oauthClientFields{
				providerCfg: oauthSrv.googleConfig,
				userInfoUrl: cfg.Google.UserInfoUrl,
				token:       &oauth2.Token{AccessToken: "accessTokenFromExchange2"},
				body:        []byte(`{"email":"test2@gmail.com","other_field":"someInfo"}`),
				exchangeErr: nil,
				getInfoErr:  nil,
			},
		},
		{
			name:              "negative incorrect provider name",
			authProvider:      "github",
			hasErr:            true,
			detailErr:         errors.New("invalid auth provider: github"),
			oauthClientFields: oauthClientFields{token: &oauth2.Token{}},
		},
		{
			name:          "negative google incorrect callback code",
			authProvider:  "google",
			hasErr:        true,
			callbackCode:  "googleIncorrectCallbackCode3",
			expectedEmail: "",
			oauthClientFields: oauthClientFields{
				providerCfg: oauthSrv.googleConfig,
				userInfoUrl: cfg.Google.UserInfoUrl,
				token:       &oauth2.Token{AccessToken: ""},
				body:        []byte(""),
				exchangeErr: errors.New("incorrect code"),
				getInfoErr:  nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			oauthClient.On(
				"Exchange",
				ctx,
				test.callbackCode,
				test.oauthClientFields.providerCfg,
			).Return(
				test.oauthClientFields.token,
				test.oauthClientFields.exchangeErr,
			).Maybe()

			oauthClient.On(
				"GetUserInfo",
				ctx,
				test.oauthClientFields.userInfoUrl,
				test.oauthClientFields.token.AccessToken,
			).Return(
				test.oauthClientFields.body,
				test.oauthClientFields.getInfoErr,
			).Maybe()

			email, err := oauthSrv.getUserEmailFromOauthProvider(ctx, test.authProvider, test.callbackCode)

			if test.hasErr {
				assert.NotNil(t, err)
				if test.detailErr != nil {
					assert.Equal(t, test.detailErr, err)
				}
			} else {
				assert.Equal(t, test.expectedEmail, email)
			}
		})
	}
}

func TestGetOrCreateUser(t *testing.T) {
	tests := []struct {
		name                         string
		authProvider                 string
		email                        string
		user                         model.User
		hasErr                       bool
		GetUserByEmailErr            error
		CreateUserWithoutPasswordErr error
		AddUserAuthProviderErr       error
		GetUserAuthProvidersErr      error
		userAuthProviders            []string
	}{
		{
			name:         "positive google existing user",
			authProvider: "google",
			email:        "existing1@gmail.com",
			user: model.User{
				Uuid:  "ffbcbc45-0d8c-4e1d-bc2a-15162a395f5b",
				Email: "existing1@gmail.com",
				PasswordHash: sql.NullString{
					String: "$2a$10$wVr/NcSjO2gYQlVpC8bL5OWhX6v.IJwZCQ7xEOb4IqZ9CuoHOqs/a",
					Valid:  true,
				},
			},
			hasErr:            false,
			userAuthProviders: []string{"google"},
		},
		{
			name:         "positive google create user",
			authProvider: "google",
			email:        "newUser1@gmail.com",
			user: model.User{
				Uuid:  "ffbcbc45-0d8c-4e1d-bc2a-15162a395f6c",
				Email: "newUser1@gmail.com",
			},
			hasErr:            false,
			GetUserByEmailErr: repository.ErrNoRows,
		},
		{
			name:              "negative yandex repo err",
			authProvider:      "yandex",
			email:             "newUser2@yandex.ru",
			hasErr:            true,
			GetUserByEmailErr: errors.New("yandex repo err"),
		},
	}

	cfg := config.MustLoadForTests()
	repo := mocks.NewIRepository(t)
	oauthClient := mocks.NewIOAuthClient(t)
	oauthSrv := New(cfg, repo, oauthClient)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			repo.On("GetUserByEmail", ctx, test.email).Return(test.user, test.GetUserByEmailErr)

			repo.On(
				"CreateUserWithoutPassword",
				ctx,
				test.email,
			).Return(
				test.user.Uuid,
				test.CreateUserWithoutPasswordErr,
			).Maybe()

			repo.On(
				"AddUserAuthProvider",
				ctx,
				test.user.Uuid,
				test.authProvider,
			).Return(
				test.AddUserAuthProviderErr,
			).Maybe()

			repo.On(
				"GetUserAuthProviders",
				ctx,
				test.user.Uuid,
			).Return(
				test.userAuthProviders,
				test.GetUserAuthProvidersErr,
			).Maybe()

			user, err := oauthSrv.getOrCreateUser(ctx, test.email, test.authProvider)

			if test.hasErr {
				assert.NotNil(t, err)
			} else {
				assert.Equal(t, test.user, user)
			}
		})
	}
}
