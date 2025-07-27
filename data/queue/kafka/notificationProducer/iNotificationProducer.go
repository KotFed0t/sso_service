package notificationProducer

import (
	"context"
	"github.com/KotFed0t/sso_service/internal/model"
)

type INotificationProducer interface {
	Send(ctx context.Context, key string, msg model.NotificationMessage)
}
