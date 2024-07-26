package httpserver

import (
	"context"
	"net/http"
	"sso_service/config"
	"time"
)

type Server struct {
	server          *http.Server
	notify          chan error
	shutdownTimeout time.Duration
}

func New(handler http.Handler, cfg *config.Config) *Server {
	httpServer := &http.Server{
		Handler:      handler,
		ReadTimeout:  cfg.HttpServer.Timeout,
		WriteTimeout: cfg.HttpServer.Timeout,
		Addr:         cfg.HttpServer.Address,
		IdleTimeout:  cfg.HttpServer.IdleTimeout,
	}

	s := &Server{
		server:          httpServer,
		notify:          make(chan error, 1),
		shutdownTimeout: cfg.HttpServer.ShutdownTimeout,
	}

	s.start()

	return s
}

func (s *Server) start() {
	go func() {
		s.notify <- s.server.ListenAndServe()
		close(s.notify)
	}()
}

func (s *Server) Notify() <-chan error {
	return s.notify
}

func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()

	return s.server.Shutdown(ctx)
}
