package controllers

import (
	"context"
	"github.com/gin-gonic/gin"
	"log/slog"
	"net/http"
	"slices"
	"sso_service/config"
	"sso_service/internal/service/serviceInterface"
)

type AuthController struct {
	cfg          *config.Config
	oauthService serviceInterface.OAuthService
}

func NewAuthController(cfg *config.Config, oauthService serviceInterface.OAuthService) *AuthController {
	return &AuthController{cfg: cfg, oauthService: oauthService}
}

func (ctrl *AuthController) Test(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"msg": "hello world"})
}

func (ctrl *AuthController) OauthLogin(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), ctrl.cfg.ApiTimeout)
	defer cancel()

	authProvider := c.Param("provider")
	if !slices.Contains(ctrl.cfg.AuthProviders, authProvider) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "invalid provider"})
		return
	}

	url, state, err := ctrl.oauthService.GetRedirectURLAndState(ctx, authProvider)
	c.SetCookie("oauthstate", state, 24*60*60, "/", "localhost", false, true)
	if err != nil {
		slog.Error("error in AuthController.OauthLogin", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"msg": "something went wrong"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"redirect_url": url})
}

func (ctrl *AuthController) OauthCallback(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), ctrl.cfg.ApiTimeout)
	defer cancel()

	oauthStateCookie, err := c.Cookie("oauthstate")
	if err != nil {
		slog.Error("failed on get oauthstate cookie", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "oauthstate cookie doesn't exist"})
		return
	}

	if c.Query("state") != oauthStateCookie {
		slog.Error("callback state does`t match oauthstate from cookie")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "callback state does`t match"})
		return
	}

	authProvider := c.Param("provider")
	if !slices.Contains(ctrl.cfg.AuthProviders, authProvider) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "invalid provider"})
		return
	}

	accessToke, refreshToken, err := ctrl.oauthService.HandleCallbackAndLoginUser(
		ctx,
		authProvider,
		c.Query("code"),
		c.ClientIP(),
	)
	if err != nil {
		slog.Error("error in AuthController.OauthCallback", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"msg": "something went wrong"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"access_token": accessToke, "refresh_token": refreshToken})
}
