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

func ValidateTokenAndGetUserUuid(tokenString string, secretKey string) (userUuid string, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", fmt.Errorf("failed on jwt.Parse: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	userUuid, err = token.Claims.GetSubject()
	if err != nil {
		return "", fmt.Errorf("failed on GetSubject from token: %w", err)
	}
	return userUuid, nil
}
