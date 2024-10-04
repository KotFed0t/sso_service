package notificationProducer

import (
	"context"
	"encoding/json"
	"github.com/segmentio/kafka-go"
	"log/slog"
	"sso_service/internal/model"
)

type NotificationProducer struct {
	writer *kafka.Writer
}

func New(kafkaUrl []string, topic string) *NotificationProducer {
	writer := &kafka.Writer{
		Addr:     kafka.TCP(kafkaUrl...),
		Topic:    topic,
		Balancer: &kafka.LeastBytes{},
	}
	return &NotificationProducer{writer: writer}
}

func (p *NotificationProducer) Send(ctx context.Context, key string, msg model.NotificationMessage) {
	kafkaValue, err := json.Marshal(msg)
	if err != nil {
		slog.Error("Error marshalling notification message", slog.Any("err", err), slog.Any("msg", msg))
	}

	slog.Info("Sending message to Kafka", slog.Any("msg", msg))
	err = p.writer.WriteMessages(ctx,
		kafka.Message{
			Key:   []byte(key),
			Value: kafkaValue,
		},
	)
	if err != nil {
		slog.Error("Error on writer.WriteMessages to notification Kafka", slog.Any("err", err), slog.Any("msg", msg))
	}
	slog.Info("msg successfully sent", slog.Any("msg", msg))
}

func (p *NotificationProducer) Close() error {
	err := p.writer.Close()
	if err != nil {
		return err
	}

	return nil
}
