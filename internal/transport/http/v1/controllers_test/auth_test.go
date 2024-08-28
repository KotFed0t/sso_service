package controllers_test

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"net/http"
	"net/http/httptest"
	"sso_service/config"
	"sso_service/internal/transport/http/v1/controllers"
	"sso_service/internal/transport/http/v1/routes"
	"sso_service/mocks"
	"testing"
)

func TestTest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.MustLoad()
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
	cfg := config.MustLoad()
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
	cfg := config.MustLoad()
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
