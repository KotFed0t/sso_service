package routes

import "sso_service/internal/transport/http/v1/controllers"
import "github.com/gin-gonic/gin"

func SetupRoutes(engine *gin.Engine, authController *controllers.AuthController) {
	apiV1Group := engine.Group("api/v1")
	oauthGroup := apiV1Group.Group("/oauth")
	authGroup := apiV1Group.Group("/auth")

	// api/v1/...
	apiV1Group.GET("/test", authController.Test)

	// api/v1/auth/...
	authGroup.POST("/register", authController.Register)
	authGroup.POST("/confirm-email", authController.ConfirmEmail)

	// api/v1/oauth/...
	oauthGroup.GET("/:provider/login", authController.OauthLogin)
	oauthGroup.GET("/:provider/callback", authController.OauthCallback)
}
