package serviceInterface

import "github.com/gin-gonic/gin"

type OAuthService interface {
	GetRedirectURL(ctx *gin.Context, authProvider string) (string, error)
	OauthProviderCallback(ctx *gin.Context, authProvider string) (string, error)
}
