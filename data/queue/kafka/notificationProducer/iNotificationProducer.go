package notificationProducer

import (
	"context"
	"sso_service/internal/model"
)

type INotificationProducer interface {
	Send(ctx context.Context, key string, msg model.NotificationMessage)
}
