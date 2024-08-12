package model

type ResetPasswordConfirmation struct {
	Email           string `json:"email" binding:"required,email"`
	Token           string `json:"token" binding:"required"`
	Password        string `json:"password" binding:"required,min=6,max=25"`
	ConfirmPassword string `json:"confirm_password" binding:"required,eqfield=Password"`
}
