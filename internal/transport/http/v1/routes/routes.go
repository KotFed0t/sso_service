package routes

import "sso_service/internal/transport/http/v1/controllers"
import "github.com/gin-gonic/gin"

func SetupRoutes(engine *gin.Engine, authController *controllers.AuthController) {
	apiV1Group := engine.Group("api/v1")
	apiV1Group.GET("/test", authController.Test)
}
