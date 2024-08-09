package model

type RegisterRequest struct {
	Email           string `json:"email" binding:"required,email"`
	Password        string `json:"password" binding:"required,min=6,max=25"`
	ConfirmPassword string `json:"confirm_password" binding:"required,eqfield=Password"`
}
