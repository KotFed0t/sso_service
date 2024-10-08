package main

import (
	"github.com/gin-gonic/gin"
	"log/slog"
	"os"
	"os/signal"
	"sso_service/config"
	"sso_service/data/db/postgres"
	"sso_service/data/queue/kafka/notificationProducer"
	"sso_service/internal/externalApi/oauthClient"
	"sso_service/internal/httpserver"
	"sso_service/internal/repository"
	"sso_service/internal/service/authService"
	"sso_service/internal/service/oauthService"
	"sso_service/internal/transport/http/v1/controllers"
	"sso_service/internal/transport/http/v1/routes"
	"syscall"
)

func main() {
	cfg := config.MustLoad()

	var logLevel slog.Level

	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(log)

	slog.Debug("config", slog.Any("cfg", cfg))

	postgresDb := postgres.MustInitPostgres(cfg)
	postgresRepo := repository.NewPostgresRepo(postgresDb)

	oauthSrv := oauthService.New(cfg, postgresRepo, &oauthClient.OauthClient{})

	notifProducer := notificationProducer.New(cfg.KafkaNotification.Url, cfg.KafkaNotification.Topic)

	authSrv := authService.New(cfg, postgresRepo, notifProducer)
	authController := controllers.NewAuthController(cfg, oauthSrv, authSrv)

	engine := gin.Default()
	routes.SetupRoutes(engine, cfg, authController)
	httpServer := httpserver.New(engine, cfg)

	// Waiting interruption signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	select {
	case s := <-interrupt:
		slog.Info("got interruption signal: " + s.String())
	case err := <-httpServer.Notify():
		slog.Error("got httpServer.Notify", slog.Any("err", err))
	}

	// Shutdown
	err := httpServer.Shutdown()
	if err != nil {
		slog.Error("httpServer.Shutdown error", slog.Any("err", err))
	}

	err = notifProducer.Close()
	if err != nil {
		slog.Error("notifProducer.Close error", slog.Any("err", err))
	}

	err = postgresDb.Close()
	if err != nil {
		slog.Error("postgresDb.Close error", slog.Any("err", err))
	}
}
