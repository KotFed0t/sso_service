package routes

import (
	"sso_service/config"
	"sso_service/internal/transport/http/v1/controllers"
	"sso_service/pkg/middleware"
)
import "github.com/gin-gonic/gin"

func SetupRoutes(engine *gin.Engine, cfg *config.Config, authController *controllers.AuthController) {
	apiV1Group := engine.Group("api/v1")
	oauthGroup := apiV1Group.Group("/oauth")
	authGroup := apiV1Group.Group("/auth")

	// api/v1/...
	apiV1Group.GET("/test", authController.Test)

	// api/v1/auth/...
	authGroup.POST("/register", authController.Register)
	authGroup.POST("/login", authController.Login)
	authGroup.POST("/logout", middleware.AuthMiddleware(cfg.Jwt.SecretKey), authController.Logout)
	authGroup.POST("/confirm-email", authController.ConfirmEmail)
	authGroup.GET("/refresh", authController.RefreshTokens)
	authGroup.POST("/reset-password", authController.SendResetPasswordLink)
	authGroup.PATCH("/reset-password", authController.ResetPassword)

	// api/v1/oauth/...
	oauthGroup.GET("/:provider/login", authController.OauthLogin)
	oauthGroup.GET("/:provider/callback", authController.OauthCallback)
}
