package controllers

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type AuthController struct{}

func NewAuthController() *AuthController {
	return &AuthController{}
}

func (c *AuthController) Test(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{"msg": "hello world"})
}
