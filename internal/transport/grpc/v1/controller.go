package v1

import (
	"context"
	"errors"
	"log/slog"
	"regexp"

	"github.com/KotFed0t/sso_service/config"
	"github.com/KotFed0t/sso_service/internal/service"
	"github.com/KotFed0t/sso_service/internal/service/serviceInterface"
	v1 "github.com/KotFed0t/sso_service/pkg/proto/sso/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GRPCController struct {
	v1.UnimplementedSSOServiceServer
	cfg         *config.Config
	authService serviceInterface.IAuthService
}

func NewGRPCController(cfg *config.Config, authService serviceInterface.IAuthService) *GRPCController {
	return &GRPCController{
		cfg:         cfg,
		authService: authService,
	}
}

func (c *GRPCController) Register(ctx context.Context, req *v1.RegisterRequest) (*v1.RegisterResponse, error) {
	email := req.GetEmail()
	reEmail := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	if email == "" || !reEmail.MatchString(email) {
		return nil, status.Error(codes.InvalidArgument, "invalid email")
	}

	passwordLen := len([]rune(req.GetPassword()))
	if passwordLen < 5 || passwordLen > 25 {
		return nil, status.Error(codes.InvalidArgument, "password length must be min=6 and max=25")
	}

	if req.GetPassword() != req.GetConfirmPassword() {
		return nil, status.Error(codes.InvalidArgument, "passwords is not equal")
	}

	err := c.authService.FirstRegistrationPhase(ctx, email, req.GetPassword())
	if err != nil {
		if errors.Is(err, service.ErrUserAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}

		slog.Error("error in AuthController.Register", slog.Any("error", err))
		return nil, status.Error(codes.Internal, "something went wrong")
	}

	return &v1.RegisterResponse{Message: "ok"}, nil
}

func (c *GRPCController) ConfirmEmail(ctx context.Context, req *v1.ConfirmEmailRequest) (*v1.ConfirmEmailResponse, error) {
	email := req.GetEmail()
	reEmail := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	if email == "" || !reEmail.MatchString(email) {
		return nil, status.Error(codes.InvalidArgument, "invalid email")
	}

	if req.GetClientIp() == "" {
		return nil, status.Error(codes.InvalidArgument, "client_ip is required")
	}

	if req.GetCode() == 0 {
		return nil, status.Error(codes.InvalidArgument, "code is required")
	}

	accessToken, refreshToken, err := c.authService.ConfirmEmailAndFinishRegistration(ctx, req.GetEmail(), int(req.GetCode()), req.GetClientIp())
	if err != nil {
		if errors.Is(err, service.ErrWrongCodeOrExpired) {
			return nil, status.Error(codes.InvalidArgument, "invalid code")
		}
		slog.Error("error in AuthController.ConfirmEmail on ConfirmEmailAndFinishRegistration", slog.Any("error", err))
		return nil, status.Error(codes.Internal, "something went wrong")
	}

	return &v1.ConfirmEmailResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (c *GRPCController) Login(ctx context.Context, req *v1.LoginRequest) (*v1.LoginResponse, error) {
	email := req.GetEmail()
	reEmail := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	if email == "" || !reEmail.MatchString(email) {
		return nil, status.Error(codes.InvalidArgument, "invalid email")
	}

	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	if req.GetClientIp() == "" {
		return nil, status.Error(codes.InvalidArgument, "client_ip is required")
	}

	accessToken, refreshToken, err := c.authService.LoginUser(ctx, req.GetEmail(), req.GetPassword(), req.GetClientIp())
	if err != nil {
		if errors.Is(err, service.ErrWrongEmailOrPassword) {
			return nil, status.Error(codes.InvalidArgument, "email or password is wrong")
		}
		slog.Error("error in AuthController.Login on authService.LoginUser", slog.Any("error", err))
		return nil, status.Error(codes.Internal, "something went wrong")
	}

	return &v1.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (c *GRPCController) Logout(ctx context.Context, req *v1.LogoutRequest) (*v1.LogoutResponse, error) {
	if req.GetRefreshToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	err := c.authService.Logout(ctx, req.GetRefreshToken())
	if err != nil {
		slog.Error("error in AuthController.Logout on authService.Logout", slog.Any("error", err))
		return nil, status.Error(codes.Internal, "something went wrong")
	}

	return &v1.LogoutResponse{Message: "ok"}, nil
}

func (c *GRPCController) RefreshTokens(ctx context.Context, req *v1.RefreshTokensRequest) (*v1.RefreshTokensResponse, error) {
	if req.GetRefreshToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	if req.GetClientIp() == "" {
		return nil, status.Error(codes.InvalidArgument, "client_ip is required")
	}

	accessToken, refreshToken, err := c.authService.RefreshTokens(ctx, req.GetRefreshToken(), req.GetClientIp())
	if err != nil {
		if errors.Is(err, service.ErrInvalidRefreshToken) {
			return nil, status.Error(codes.InvalidArgument, "invalid refresh token")
		}
		slog.Error("error in AuthController.RefreshTokens on authService.RefreshTokens", slog.Any("error", err))
		return nil, status.Error(codes.Internal, "something went wrong")
	}

	return &v1.RefreshTokensResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
