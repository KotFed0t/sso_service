package grpcserver

import (
	"fmt"
	"net"

	"github.com/KotFed0t/sso_service/config"
	ctrl "github.com/KotFed0t/sso_service/internal/transport/grpc/v1"
	v1 "github.com/KotFed0t/sso_service/pkg/proto/sso/v1"
	"google.golang.org/grpc"
)

type GRPCServer struct {
	cfg            *config.Config
	server         *grpc.Server
	grpcController *ctrl.GRPCController
	notify         chan error
}

func NewGRPCServer(cfg *config.Config, grpcController *ctrl.GRPCController) *GRPCServer {
	return &GRPCServer{
		cfg:            cfg,
		server:         grpc.NewServer(),
		grpcController: grpcController,
		notify:         make(chan error),
	}
}

func (s *GRPCServer) registerHandlers() {
	v1.RegisterSSOServiceServer(s.server, s.grpcController)
}

func (s *GRPCServer) Start() {
	s.registerHandlers()

	go func() {
		listener, err := net.Listen("tcp", s.cfg.GRPCServer.Address)
		if err != nil {
			s.notify <- fmt.Errorf("failed to listen: %w", err)
			close(s.notify)
			return
		}

		s.notify <- s.server.Serve(listener)
		close(s.notify)
	}()
}

func (s *GRPCServer) Notify() <-chan error {
	return s.notify
}
func (s *GRPCServer) Shutdown() {
	s.server.GracefulStop()
}
