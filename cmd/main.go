package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/KotFed0t/sso_service/config"
	"github.com/KotFed0t/sso_service/data/db/postgres"
	"github.com/KotFed0t/sso_service/data/queue/kafka/notificationProducer"
	"github.com/KotFed0t/sso_service/internal/externalApi/oauthClient"
	"github.com/KotFed0t/sso_service/internal/grpcserver"
	"github.com/KotFed0t/sso_service/internal/httpserver"
	"github.com/KotFed0t/sso_service/internal/repository"
	"github.com/KotFed0t/sso_service/internal/service/authService"
	"github.com/KotFed0t/sso_service/internal/service/oauthService"
	v1 "github.com/KotFed0t/sso_service/internal/transport/grpc/v1"
	"github.com/KotFed0t/sso_service/internal/transport/http/v1/controllers"
	"github.com/KotFed0t/sso_service/internal/transport/http/v1/routes"
	"github.com/gin-gonic/gin"
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

	grpcController := v1.NewGRPCController(cfg, authSrv)
	grpcServer := grpcserver.NewGRPCServer(cfg, grpcController)
	grpcServer.Start()

	// Waiting interruption signal
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	select {
	case s := <-interrupt:
		slog.Info("got interruption signal: " + s.String())
	case err := <-httpServer.Notify():
		slog.Error("got httpServer.Notify", slog.Any("err", err))
	case err := <-grpcServer.Notify():
		slog.Error("got grpcServer.Notify", slog.Any("err", err))
	}

	// Shutdown
	err := httpServer.Shutdown()
	if err != nil {
		slog.Error("httpServer.Shutdown error", slog.Any("err", err))
	}

	grpcServer.Shutdown()

	err = notifProducer.Close()
	if err != nil {
		slog.Error("notifProducer.Close error", slog.Any("err", err))
	}

	err = postgresDb.Close()
	if err != nil {
		slog.Error("postgresDb.Close error", slog.Any("err", err))
	}
}
