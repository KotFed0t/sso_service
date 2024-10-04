package model

type NotificationMessage struct {
	Email        string            `json:"email"`
	Subject      string            `json:"subject"`
	TemplateName string            `json:"template_name"`
	Parameters   map[string]string `json:"parameters"`
}
