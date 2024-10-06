package controllers_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"net/http"
	"net/http/httptest"
	"sso_service/config"
	"sso_service/internal/model"
	"sso_service/internal/service"
	"sso_service/internal/transport/http/v1/controllers"
	"sso_service/internal/transport/http/v1/routes"
	"sso_service/internal/utils"
	"sso_service/mocks"
	"testing"
	"time"
)

func TestTest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.MustLoadForTests()
	engine := gin.Default()
	authSrv := mocks.NewIAuthService(t)
	oauthSrv := mocks.NewIOAuthService(t)
	authController := controllers.NewAuthController(cfg, oauthSrv, authSrv)
	routes.SetupRoutes(engine, cfg, authController)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/v1/test", nil)
	engine.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"msg":"hello world"}`, w.Body.String())
}

func TestOauthLogin(t *testing.T) {
	tests := []struct {
		name         string
		provider     string
		expectedBody string
		redirectUrl  string
		expectedCode int
	}{
		{
			name:         "positive yandex",
			provider:     "yandex",
			expectedBody: `{"redirect_url":"https://yandex/oauth"}`,
			expectedCode: http.StatusOK,
			redirectUrl:  "https://yandex/oauth",
		},
		{
			name:         "positive google",
			provider:     "google",
			expectedBody: `{"redirect_url":"https://google/oauth"}`,
			expectedCode: http.StatusOK,
			redirectUrl:  "https://google/oauth",
		},
		{
			name:         "incorrect provider",
			provider:     "amazon",
			expectedBody: `{"error":"invalid provider"}`,
			expectedCode: http.StatusBadRequest,
			redirectUrl:  "",
		},
	}

	gin.SetMode(gin.TestMode)
	cfg := config.MustLoadForTests()
	engine := gin.Default()
	authSrv := mocks.NewIAuthService(t)
	oauthSrv := mocks.NewIOAuthService(t)
	authController := controllers.NewAuthController(cfg, oauthSrv, authSrv)
	routes.SetupRoutes(engine, cfg, authController)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oauthSrv.
				On("GetRedirectURLAndState", mock.Anything, test.provider).
				Return(test.redirectUrl, "", nil).
				Maybe()

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", fmt.Sprintf("/api/v1/oauth/%s/login", test.provider), nil)
			engine.ServeHTTP(w, req)
			assert.Equal(t, test.expectedCode, w.Code)
			assert.Equal(t, test.expectedBody, w.Body.String())
		})
	}
}

func TestOauthCallback(t *testing.T) {
	type oauthSrvFields struct {
		error        error
		accessToken  string
		refreshToken string
	}

	tests := []struct {
		name          string
		provider      string
		expectedBody  string
		expectedCode  int
		cookieName    string
		cookieValue   string
		callbackState string
		callbackCode  string
		oauthSrv      oauthSrvFields
	}{
		{
			name:          "positive yandex",
			provider:      "yandex",
			expectedBody:  `{"access_token":"accessToken","refresh_token":"refreshToken"}`,
			expectedCode:  http.StatusOK,
			cookieName:    "oauthstate",
			cookieValue:   "yandexStateCode",
			callbackState: "yandexStateCode",
			callbackCode:  "callbackCode",
			oauthSrv: oauthSrvFields{
				error:        nil,
				accessToken:  "accessToken",
				refreshToken: "refreshToken",
			},
		},
		{
			name:          "positive google",
			provider:      "google",
			expectedBody:  `{"access_token":"accessToken","refresh_token":"refreshToken"}`,
			expectedCode:  http.StatusOK,
			cookieName:    "oauthstate",
			cookieValue:   "googleStateCode",
			callbackState: "googleStateCode",
			callbackCode:  "callbackCode",
			oauthSrv: oauthSrvFields{
				error:        nil,
				accessToken:  "accessToken",
				refreshToken: "refreshToken",
			},
		},
		{
			name:          "negative callback state doesn't match",
			provider:      "google",
			expectedBody:  `{"error":"callback state doesn't match"}`,
			expectedCode:  http.StatusBadRequest,
			cookieName:    "oauthstate",
			cookieValue:   "googleStateCode",
			callbackState: "IncorrectGoogleStateCode",
			callbackCode:  "callbackCode",
			oauthSrv: oauthSrvFields{
				error:        nil,
				accessToken:  "accessToken",
				refreshToken: "refreshToken",
			},
		},
		{
			name:          "negative oauthstate doesn't set",
			provider:      "google",
			expectedBody:  `{"error":"oauthstate cookie doesn't exist"}`,
			expectedCode:  http.StatusBadRequest,
			cookieName:    "",
			cookieValue:   "",
			callbackState: "googleStateCode",
			callbackCode:  "callbackCode",
			oauthSrv: oauthSrvFields{
				error:        nil,
				accessToken:  "accessToken",
				refreshToken: "refreshToken",
			},
		},
		{
			name:          "negative incorrect provider",
			provider:      "amazon",
			expectedBody:  `{"error":"invalid provider"}`,
			expectedCode:  http.StatusBadRequest,
			cookieName:    "oauthstate",
			cookieValue:   "amazonStateCode",
			callbackState: "amazonStateCode",
			callbackCode:  "callbackCode",
			oauthSrv: oauthSrvFields{
				error:        nil,
				accessToken:  "accessToken",
				refreshToken: "refreshToken",
			},
		},
	}

	gin.SetMode(gin.TestMode)
	cfg := config.MustLoadForTests()
	engine := gin.Default()
	authSrv := mocks.NewIAuthService(t)
	oauthSrv := mocks.NewIOAuthService(t)
	authController := controllers.NewAuthController(cfg, oauthSrv, authSrv)
	routes.SetupRoutes(engine, cfg, authController)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oauthSrv.
				On("HandleCallbackAndLoginUser", mock.Anything, test.provider, test.callbackCode, mock.Anything).
				Return(test.oauthSrv.accessToken, test.oauthSrv.refreshToken, test.oauthSrv.error).
				Maybe()

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", fmt.Sprintf("/api/v1/oauth/%s/callback", test.provider), nil)
			req.AddCookie(&http.Cookie{
				Name:  test.cookieName,
				Value: test.cookieValue,
			})

			// Добавление query parameters
			q := req.URL.Query()
			q.Add("state", test.callbackState)
			q.Add("code", test.callbackCode)
			req.URL.RawQuery = q.Encode()

			engine.ServeHTTP(w, req)
			assert.Equal(t, test.expectedCode, w.Code)
			assert.Equal(t, test.expectedBody, w.Body.String())
		})
	}
}

func TestFirstRegistrationPhase(t *testing.T) {
	tests := []struct {
		name         string
		expectedBody string
		expectedCode int
		request      model.RegisterRequest
		authSrvErr   error
	}{
		{
			name:         "positive",
			expectedBody: `{"msg":"ok"}`,
			expectedCode: 200,
			request: model.RegisterRequest{
				Email:           "test@gmail.com",
				Password:        "testPass",
				ConfirmPassword: "testPass",
			},
			authSrvErr: nil,
		},
		{
			name:         "negative email already exists",
			expectedBody: `{"error":"user already exists"}`,
			expectedCode: 400,
			request: model.RegisterRequest{
				Email:           "existed@gmail.com",
				Password:        "testPass",
				ConfirmPassword: "testPass",
			},
			authSrvErr: service.ErrUserAlreadyExists,
		},
		{
			name:         "negative invalid email",
			expectedBody: `{"details":{"Email":"email"},"error":"validation error"}`,
			expectedCode: 400,
			request: model.RegisterRequest{
				Email:           "testgmail.com",
				Password:        "testPass",
				ConfirmPassword: "testPass",
			},
		},
	}

	gin.SetMode(gin.TestMode)
	cfg := config.MustLoadForTests()
	engine := gin.Default()
	authSrv := mocks.NewIAuthService(t)
	oauthSrv := mocks.NewIOAuthService(t)
	authController := controllers.NewAuthController(cfg, oauthSrv, authSrv)
	routes.SetupRoutes(engine, cfg, authController)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authSrv.
				On("FirstRegistrationPhase", mock.Anything, test.request.Email, test.request.Password).
				Return(test.authSrvErr).
				Maybe()

			jsonReq, _ := json.Marshal(test.request)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(jsonReq))

			engine.ServeHTTP(w, req)
			assert.Equal(t, test.expectedCode, w.Code)
			assert.Equal(t, test.expectedBody, w.Body.String())
		})
	}
}

func TestConfirmEmail(t *testing.T) {
	tests := []struct {
		name         string
		expectedBody string
		expectedCode int
		request      model.ConfirmEmailRequest
		authSrvErr   error
		cookieName   string
		cookieValue  string
		access       string
		refresh      string
	}{
		{
			name:         "positive",
			expectedBody: `{"access_token":"accessToken","refresh_token":"refreshToken"}`,
			expectedCode: 200,
			request:      model.ConfirmEmailRequest{Code: 111222},
			authSrvErr:   nil,
			cookieName:   "email",
			cookieValue:  "test1@gmail.com",
			access:       "accessToken",
			refresh:      "refreshToken",
		},
		{
			name:         "negative cookieEmail doesn't exists",
			expectedBody: `{"error":"something went wrong"}`,
			expectedCode: 500,
			request:      model.ConfirmEmailRequest{Code: 111222},
			authSrvErr:   nil,
		},
		{
			name:         "negative wrong or expired code",
			expectedBody: `{"error":"invalid code"}`,
			expectedCode: 400,
			request:      model.ConfirmEmailRequest{Code: 999999},
			authSrvErr:   service.ErrWrongCodeOrExpired,
			cookieName:   "email",
			cookieValue:  "test3@gmail.com",
			access:       "accessToken",
			refresh:      "refreshToken",
		},
	}

	gin.SetMode(gin.TestMode)
	cfg := config.MustLoadForTests()
	engine := gin.Default()
	authSrv := mocks.NewIAuthService(t)
	oauthSrv := mocks.NewIOAuthService(t)
	authController := controllers.NewAuthController(cfg, oauthSrv, authSrv)
	routes.SetupRoutes(engine, cfg, authController)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authSrv.
				On(
					"ConfirmEmailAndFinishRegistration",
					mock.Anything,
					test.cookieValue,
					test.request.Code,
					mock.Anything,
				).
				Return(test.access, test.refresh, test.authSrvErr).
				Maybe()

			jsonReq, _ := json.Marshal(test.request)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/api/v1/auth/confirm-email", bytes.NewBuffer(jsonReq))

			req.AddCookie(&http.Cookie{
				Name:  test.cookieName,
				Value: test.cookieValue,
			})

			engine.ServeHTTP(w, req)
			assert.Equal(t, test.expectedCode, w.Code)
			assert.Equal(t, test.expectedBody, w.Body.String())
		})
	}
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name         string
		expectedBody string
		expectedCode int
		request      model.LoginRequest
		authSrvErr   error
		access       string
		refresh      string
	}{
		{
			name:         "positive",
			expectedBody: `{"access_token":"accessToken","refresh_token":"refreshToken"}`,
			expectedCode: 200,
			request:      model.LoginRequest{Email: "test1@gmail.com", Password: "testPass"},
			authSrvErr:   nil,
			access:       "accessToken",
			refresh:      "refreshToken",
		},
		{
			name:         "negative wrong email or password",
			expectedBody: `{"error":"email or password is wrong"}`,
			expectedCode: 400,
			request:      model.LoginRequest{Email: "test2@gmail.com", Password: "testPass"},
			authSrvErr:   service.ErrWrongEmailOrPassword,
			access:       "",
			refresh:      "",
		},
		{
			name:         "negative invalid email",
			expectedBody: `{"details":{"Email":"email"},"error":"validation error"}`,
			expectedCode: 400,
			request:      model.LoginRequest{Email: "invalid.gmail.com", Password: "testPass"},
			authSrvErr:   service.ErrWrongEmailOrPassword,
			access:       "",
			refresh:      "",
		},
	}

	gin.SetMode(gin.TestMode)
	cfg := config.MustLoadForTests()
	engine := gin.Default()
	authSrv := mocks.NewIAuthService(t)
	oauthSrv := mocks.NewIOAuthService(t)
	authController := controllers.NewAuthController(cfg, oauthSrv, authSrv)
	routes.SetupRoutes(engine, cfg, authController)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authSrv.
				On(
					"LoginUser",
					mock.Anything,
					test.request.Email,
					test.request.Password,
					mock.Anything,
				).
				Return(test.access, test.refresh, test.authSrvErr).
				Maybe()

			jsonReq, _ := json.Marshal(test.request)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonReq))

			engine.ServeHTTP(w, req)
			assert.Equal(t, test.expectedCode, w.Code)
			assert.Equal(t, test.expectedBody, w.Body.String())
		})
	}
}

func TestRefreshToken(t *testing.T) {
	tests := []struct {
		name         string
		expectedBody string
		expectedCode int
		authSrvErr   error
		cookieName   string
		cookieValue  string
		access       string
		refresh      string
	}{
		{
			name:         "positive",
			expectedBody: `{"access_token":"newAccessToken","refresh_token":"newRefreshToken"}`,
			expectedCode: 200,
			authSrvErr:   nil,
			cookieName:   "refreshToken",
			cookieValue:  "refreshTokenFromCookie",
			access:       "newAccessToken",
			refresh:      "newRefreshToken",
		},
		{
			name:         "negative cookie doesn't exists",
			expectedBody: `{"error":"something went wrong"}`,
			expectedCode: 500,
			authSrvErr:   nil,
			cookieName:   "",
			cookieValue:  "",
			access:       "",
			refresh:      "",
		},
		{
			name:         "negative invalid refresh token",
			expectedBody: `{"error":"invalid refresh token"}`,
			expectedCode: 400,
			authSrvErr:   service.ErrInvalidRefreshToken,
			cookieName:   "refreshToken",
			cookieValue:  "invalidRefreshToken",
			access:       "",
			refresh:      "",
		},
	}

	gin.SetMode(gin.TestMode)
	cfg := config.MustLoadForTests()
	engine := gin.Default()
	authSrv := mocks.NewIAuthService(t)
	oauthSrv := mocks.NewIOAuthService(t)
	authController := controllers.NewAuthController(cfg, oauthSrv, authSrv)
	routes.SetupRoutes(engine, cfg, authController)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authSrv.
				On(
					"RefreshTokens",
					mock.Anything,
					test.cookieValue,
					mock.Anything,
				).
				Return(test.access, test.refresh, test.authSrvErr).
				Maybe()

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/api/v1/auth/refresh", nil)
			req.AddCookie(&http.Cookie{
				Name:  test.cookieName,
				Value: test.cookieValue,
			})

			engine.ServeHTTP(w, req)
			assert.Equal(t, test.expectedCode, w.Code)
			assert.Equal(t, test.expectedBody, w.Body.String())
		})
	}
}

func TestResetPassword(t *testing.T) {
	tests := []struct {
		name         string
		expectedBody string
		expectedCode int
		request      model.ResetPasswordConfirmation
		authSrvErr   error
	}{
		{
			name:         "positive",
			expectedBody: `{"msg":"ok"}`,
			expectedCode: 200,
			request: model.ResetPasswordConfirmation{
				Uuid:            "ffbcbc45-0d8c-4e1d-bc2a-15562a395f4b",
				Token:           "uniqueToken",
				Password:        "testPass",
				ConfirmPassword: "testPass",
			},
			authSrvErr: nil,
		},
		{
			name:         "negative invalid token or expired token",
			expectedBody: `{"error":"invalid data or expired token"}`,
			expectedCode: 400,
			request: model.ResetPasswordConfirmation{
				Uuid:            "ffbcbc45-0d8c-4e1d-bc2a-15562a395f4b",
				Token:           "expiredOrInvalidToken",
				Password:        "testPass",
				ConfirmPassword: "testPass",
			},
			authSrvErr: service.ErrResetPasswordNotValidOrExpired,
		},
	}

	gin.SetMode(gin.TestMode)
	cfg := config.MustLoadForTests()
	engine := gin.Default()
	authSrv := mocks.NewIAuthService(t)
	oauthSrv := mocks.NewIOAuthService(t)
	authController := controllers.NewAuthController(cfg, oauthSrv, authSrv)
	routes.SetupRoutes(engine, cfg, authController)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authSrv.
				On(
					"ResetPassword",
					mock.Anything,
					test.request.Uuid,
					test.request.Token,
					test.request.Password,
				).
				Return(test.authSrvErr).
				Maybe()

			jsonReq, _ := json.Marshal(test.request)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("PATCH", "/api/v1/auth/reset-password", bytes.NewBuffer(jsonReq))

			engine.ServeHTTP(w, req)
			assert.Equal(t, test.expectedCode, w.Code)
			assert.Equal(t, test.expectedBody, w.Body.String())
		})
	}
}

func TestLogout(t *testing.T) {
	tests := []struct {
		name                           string
		expectedBody                   string
		expectedCode                   int
		authSrvErr                     error
		cookieName                     string
		cookieValue                    string
		isAuthorizationTokenTransfered bool
	}{
		{
			name:                           "positive",
			expectedBody:                   `{"msg":"ok"}`,
			expectedCode:                   200,
			authSrvErr:                     nil,
			cookieName:                     "refreshToken",
			cookieValue:                    "refreshTokenFromCookie1",
			isAuthorizationTokenTransfered: true,
		},
		{
			name:                           "negative authorization token didn't transfer",
			expectedBody:                   `{"error":"Authorization header missing or invalid"}`,
			expectedCode:                   401,
			authSrvErr:                     nil,
			cookieName:                     "refreshToken",
			cookieValue:                    "refreshTokenFromCookie2",
			isAuthorizationTokenTransfered: false,
		},
		{
			name:                           "negative refreshToken cookie doesn't exists",
			expectedBody:                   `{"error":"something went wrong"}`,
			expectedCode:                   500,
			authSrvErr:                     nil,
			cookieName:                     "",
			cookieValue:                    "",
			isAuthorizationTokenTransfered: true,
		},
		{
			name:                           "negative authSrv returned error",
			expectedBody:                   `{"error":"something went wrong"}`,
			expectedCode:                   500,
			authSrvErr:                     errors.New("something went wrong"),
			cookieName:                     "refreshToken",
			cookieValue:                    "refreshTokenFromCookie3",
			isAuthorizationTokenTransfered: true,
		},
	}

	gin.SetMode(gin.TestMode)
	cfg := config.MustLoadForTests()
	engine := gin.Default()
	authSrv := mocks.NewIAuthService(t)
	oauthSrv := mocks.NewIOAuthService(t)
	authController := controllers.NewAuthController(cfg, oauthSrv, authSrv)
	routes.SetupRoutes(engine, cfg, authController)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authSrv.
				On(
					"Logout",
					mock.Anything,
					test.cookieValue,
				).
				Return(test.authSrvErr).
				Maybe()

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/api/v1/auth/logout", nil)

			req.AddCookie(&http.Cookie{
				Name:  test.cookieName,
				Value: test.cookieValue,
			})

			if test.isAuthorizationTokenTransfered {
				claims := jwt.MapClaims{
					"sub": "fd1baff2-7439-4d75-bde3-2617aef1e808",
					"exp": time.Now().Add(cfg.Jwt.AccessTokenTtl).Unix(),
				}
				accessToken, _ := utils.GenerateJWT(cfg.Jwt.SecretKey, claims)
				req.Header.Add("Authorization", "Bearer "+accessToken)
			}

			engine.ServeHTTP(w, req)
			assert.Equal(t, test.expectedCode, w.Code)
			assert.Equal(t, test.expectedBody, w.Body.String())
		})
	}
}
