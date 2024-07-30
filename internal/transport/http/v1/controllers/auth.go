package controllers

import (
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

func (c *AuthController) Test(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"msg": "hello world"})
}

func (c *AuthController) OauthLogin(ctx *gin.Context) {
	authProvider := ctx.Param("provider")
	if !slices.Contains(c.cfg.AuthProviders, authProvider) {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "invalid provider"})
		return
	}
	url, err := c.oauthService.GetRedirectURL(ctx, authProvider)
	if err != nil {
		slog.Error("error in AuthController.OauthLogin", slog.Any("error", err))
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"msg": "something went wrong"})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"redirect_url": url})
}

func (c *AuthController) OauthCallback(ctx *gin.Context) {
	authProvider := ctx.Param("provider")
	if !slices.Contains(c.cfg.AuthProviders, authProvider) {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"msg": "invalid provider"})
		return
	}
	email, err := c.oauthService.OauthProviderCallback(ctx, authProvider)
	if err != nil {
		slog.Error("error in AuthController.OauthCallback", slog.Any("error", err))
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"msg": "something went wrong"})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"email": email})
}
