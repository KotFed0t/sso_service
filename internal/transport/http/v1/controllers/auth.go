package controllers

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"log/slog"
	"net/http"
	"slices"
	"sso_service/config"
	"sso_service/internal/model"
	"sso_service/internal/service"
	"sso_service/internal/service/serviceInterface"
	"sso_service/internal/utils"
)

type AuthController struct {
	cfg          *config.Config
	oauthService serviceInterface.IOAuthService
	authService  serviceInterface.IAuthService
}

func NewAuthController(cfg *config.Config, oauthService serviceInterface.IOAuthService, authService serviceInterface.IAuthService) *AuthController {
	return &AuthController{cfg: cfg, oauthService: oauthService, authService: authService}
}

func (ctrl *AuthController) Test(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"msg": "hello world"})
}

func (ctrl *AuthController) OauthLogin(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), ctrl.cfg.ApiTimeout)
	defer cancel()

	authProvider := c.Param("provider")
	if !slices.Contains(ctrl.cfg.AuthProviders, authProvider) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	url, state, err := ctrl.oauthService.GetRedirectURLAndState(ctx, authProvider)
	c.SetCookie("oauthstate", state, 24*60*60, "/", "", false, true)
	if err != nil {
		slog.Error("error in AuthController.OauthLogin", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
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
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "oauthstate cookie doesn't exist"})
		return
	}

	if c.Query("state") != oauthStateCookie {
		slog.Error("callback state does`t match oauthstate from cookie")
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "callback state doesn't match"})
		return
	}

	authProvider := c.Param("provider")
	if !slices.Contains(ctrl.cfg.AuthProviders, authProvider) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	accessToken, refreshToken, err := ctrl.oauthService.HandleCallbackAndLoginUser(
		ctx,
		authProvider,
		c.Query("code"),
		c.ClientIP(),
	)
	if err != nil {
		slog.Error("error in AuthController.OauthCallback", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		return
	}

	c.SetCookie("oauthstate", "", -1, "/", "", false, true)
	c.SetCookie("refreshToken", refreshToken, 30*24*60*60, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": refreshToken})
}

func (ctrl *AuthController) Register(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), ctrl.cfg.ApiTimeout)
	defer cancel()

	var request model.RegisterRequest
	err := c.ShouldBindJSON(&request)
	if err != nil {
		if errMessages, ok := utils.GetErrorsFromRequestValidation(err); ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "validation error", "details": errMessages})
			return
		}

		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	err = ctrl.authService.FirstRegistrationPhase(ctx, request.Email, request.Password)
	if err != nil {
		slog.Error("error in AuthController.Register", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		return
	}

	c.SetCookie("email", request.Email, 2*60*60, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"msg": "ok"})
}

func (ctrl *AuthController) ConfirmEmail(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), ctrl.cfg.ApiTimeout)
	defer cancel()

	var request model.ConfirmEmailRequest
	err := c.ShouldBindJSON(&request)
	if err != nil {
		if errMessages, ok := utils.GetErrorsFromRequestValidation(err); ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "validation error", "details": errMessages})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	email, err := c.Cookie("email")
	if err != nil {
		slog.Error("error in AuthController.ConfirmEmail on getting cookie email", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		return
	}

	accessToken, refreshToken, err := ctrl.authService.ConfirmEmailAndFinishRegistration(
		ctx,
		email,
		request.Code,
		c.ClientIP(),
	)
	if err != nil {
		if errors.Is(err, service.ErrWrongCodeOrExpired) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid code"})
			return
		}
		slog.Error("error in AuthController.ConfirmEmail on ConfirmEmailAndFinishRegistration", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		return
	}

	c.SetCookie("email", "", -1, "/", "", false, true)
	c.SetCookie("refreshToken", refreshToken, 30*24*60*60, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": refreshToken})
}

func (ctrl *AuthController) Login(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), ctrl.cfg.ApiTimeout)
	defer cancel()

	var request model.LoginRequest
	err := c.ShouldBindJSON(&request)
	if err != nil {
		if errMessages, ok := utils.GetErrorsFromRequestValidation(err); ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "validation error", "details": errMessages})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	accessToken, refreshToken, err := ctrl.authService.LoginUser(ctx, request.Email, request.Password, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrWrongEmailOrPassword) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "email or password is wrong"})
			return
		}
		slog.Error("error in AuthController.Login on authService.LoginUser", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		return
	}
	c.SetCookie("refreshToken", refreshToken, 30*24*60*60, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": refreshToken})
}

func (ctrl *AuthController) RefreshTokens(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), ctrl.cfg.ApiTimeout)
	defer cancel()

	refreshToken, err := c.Cookie("refreshToken")
	if err != nil {
		slog.Error("error in AuthController.RefreshTokens on getting cookie refreshToken", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		return
	}

	accessToken, refreshToken, err := ctrl.authService.RefreshTokens(ctx, refreshToken, c.ClientIP())
	if err != nil {
		if errors.Is(err, service.ErrInvalidRefreshToken) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid refresh token"})
			return
		}
		slog.Error("error in AuthController.RefreshTokens on authService.RefreshTokens", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		return
	}
	c.SetCookie("refreshToken", refreshToken, 30*24*60*60, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": refreshToken})
}

func (ctrl *AuthController) SendResetPasswordLink(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), ctrl.cfg.ApiTimeout)
	defer cancel()

	var request model.ResetPasswordRequest
	err := c.ShouldBindJSON(&request)
	if err != nil {
		if errMessages, ok := utils.GetErrorsFromRequestValidation(err); ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "validation error", "details": errMessages})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	err = ctrl.authService.SendResetPasswordLink(ctx, request.Email)
	if err != nil {
		slog.Error("error in AuthController.RefreshTokens on authService.SendResetPasswordLink", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "ok"})
}

func (ctrl *AuthController) ResetPassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), ctrl.cfg.ApiTimeout)
	defer cancel()

	var request model.ResetPasswordConfirmation
	err := c.ShouldBindJSON(&request)
	if err != nil {
		if errMessages, ok := utils.GetErrorsFromRequestValidation(err); ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "validation error", "details": errMessages})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	err = ctrl.authService.ResetPassword(ctx, request.Uuid, request.Token, request.Password)
	if err != nil {
		if errors.Is(err, service.ErrResetPasswordNotValidOrExpired) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid data or expired token"})
			return
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "ok"})
}

func (ctrl *AuthController) Logout(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), ctrl.cfg.ApiTimeout)
	defer cancel()

	refreshToken, err := c.Cookie("refreshToken")
	if err != nil {
		slog.Error("error in AuthController.Logout on getting cookie refreshToken", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		return
	}

	err = ctrl.authService.Logout(ctx, refreshToken)
	if err != nil {
		slog.Error("error in AuthController.Logout on authService.Logout", slog.Any("error", err))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "something went wrong"})
		return
	}

	c.SetCookie("refreshToken", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"msg": "ok"})
}
