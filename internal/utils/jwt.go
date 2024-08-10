package utils

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func GenerateJWT(secret string, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func GenerateAccessAndRefreshTokens(
	userUuid string,
	accessTokenTtl time.Duration,
	refreshTokenTtl time.Duration,
	secretKey string,
) (accessToken, refreshToken string, err error) {
	claims := jwt.MapClaims{
		"sub": userUuid,
		"exp": time.Now().Add(accessTokenTtl).Unix(),
	}
	accessToken, err = GenerateJWT(secretKey, claims)
	if err != nil {
		return "", "", fmt.Errorf("failed on GenerateJWT accessToken: %w", err)
	}

	claims = jwt.MapClaims{
		"sub": userUuid,
		"exp": time.Now().Add(refreshTokenTtl).Unix(),
	}
	refreshToken, err = GenerateJWT(secretKey, claims)
	if err != nil {
		return "", "", fmt.Errorf("failed on GenerateJWT accessToken: %w", err)
	}

	return accessToken, refreshToken, nil
}
