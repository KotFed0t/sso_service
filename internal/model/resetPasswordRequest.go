package model

type ResetPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}
