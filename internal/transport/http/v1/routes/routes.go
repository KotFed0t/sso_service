package routes

import "sso_service/internal/transport/http/v1/controllers"
import "github.com/gin-gonic/gin"

func SetupRoutes(engine *gin.Engine, authController *controllers.AuthController) {
	apiV1Group := engine.Group("api/v1")
	oauthGroup := apiV1Group.Group("/oauth")

	// api/v1/...
	apiV1Group.GET("/test", authController.Test)

	// api/v1/oauth/...
	oauthGroup.GET("/:provider/login", authController.OauthLogin)
	oauthGroup.GET("/:provider/callback", authController.OauthCallback)
}
