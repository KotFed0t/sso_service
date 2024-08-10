package model

type ConfirmEmailRequest struct {
	Code int `json:"code" binding:"required"`
}
