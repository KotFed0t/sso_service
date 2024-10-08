// Code generated by mockery v2.45.0. DO NOT EDIT.

package mocks

import (
	context "context"
	model "sso_service/internal/model"

	mock "github.com/stretchr/testify/mock"

	time "time"
)

// IRepository is an autogenerated mock type for the IRepository type
type IRepository struct {
	mock.Mock
}

// AddUserAuthProvider provides a mock function with given fields: ctx, userUuid, providerName
func (_m *IRepository) AddUserAuthProvider(ctx context.Context, userUuid string, providerName string) error {
	ret := _m.Called(ctx, userUuid, providerName)

	if len(ret) == 0 {
		panic("no return value specified for AddUserAuthProvider")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, userUuid, providerName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CheckExistenceUserUuidInRefreshTokens provides a mock function with given fields: ctx, userUuid
func (_m *IRepository) CheckExistenceUserUuidInRefreshTokens(ctx context.Context, userUuid string) (bool, error) {
	ret := _m.Called(ctx, userUuid)

	if len(ret) == 0 {
		panic("no return value specified for CheckExistenceUserUuidInRefreshTokens")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (bool, error)); ok {
		return rf(ctx, userUuid)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) bool); ok {
		r0 = rf(ctx, userUuid)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, userUuid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CheckRefreshTokenExistence provides a mock function with given fields: ctx, userUuid, refreshToken, clientIp
func (_m *IRepository) CheckRefreshTokenExistence(ctx context.Context, userUuid string, refreshToken string, clientIp string) (bool, error) {
	ret := _m.Called(ctx, userUuid, refreshToken, clientIp)

	if len(ret) == 0 {
		panic("no return value specified for CheckRefreshTokenExistence")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) (bool, error)); ok {
		return rf(ctx, userUuid, refreshToken, clientIp)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) bool); ok {
		r0 = rf(ctx, userUuid, refreshToken, clientIp)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, userUuid, refreshToken, clientIp)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CheckResetPasswordTokenAndUuidExistence provides a mock function with given fields: ctx, uuid, token
func (_m *IRepository) CheckResetPasswordTokenAndUuidExistence(ctx context.Context, uuid string, token string) (bool, error) {
	ret := _m.Called(ctx, uuid, token)

	if len(ret) == 0 {
		panic("no return value specified for CheckResetPasswordTokenAndUuidExistence")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (bool, error)); ok {
		return rf(ctx, uuid, token)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) bool); ok {
		r0 = rf(ctx, uuid, token)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, uuid, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CheckUserExists provides a mock function with given fields: ctx, email
func (_m *IRepository) CheckUserExists(ctx context.Context, email string) (bool, error) {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for CheckUserExists")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (bool, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) bool); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateUserWithPassword provides a mock function with given fields: ctx, email, passwordHash
func (_m *IRepository) CreateUserWithPassword(ctx context.Context, email string, passwordHash string) (string, error) {
	ret := _m.Called(ctx, email, passwordHash)

	if len(ret) == 0 {
		panic("no return value specified for CreateUserWithPassword")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (string, error)); ok {
		return rf(ctx, email, passwordHash)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) string); ok {
		r0 = rf(ctx, email, passwordHash)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, email, passwordHash)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateUserWithoutPassword provides a mock function with given fields: ctx, email
func (_m *IRepository) CreateUserWithoutPassword(ctx context.Context, email string) (string, error) {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for CreateUserWithoutPassword")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeletePendingUser provides a mock function with given fields: ctx, email
func (_m *IRepository) DeletePendingUser(ctx context.Context, email string) error {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for DeletePendingUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteRefreshToken provides a mock function with given fields: ctx, refreshToken
func (_m *IRepository) DeleteRefreshToken(ctx context.Context, refreshToken string) error {
	ret := _m.Called(ctx, refreshToken)

	if len(ret) == 0 {
		panic("no return value specified for DeleteRefreshToken")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, refreshToken)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteUuidFromPasswordReset provides a mock function with given fields: ctx, uuid
func (_m *IRepository) DeleteUuidFromPasswordReset(ctx context.Context, uuid string) error {
	ret := _m.Called(ctx, uuid)

	if len(ret) == 0 {
		panic("no return value specified for DeleteUuidFromPasswordReset")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, uuid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetPendingUser provides a mock function with given fields: ctx, email
func (_m *IRepository) GetPendingUser(ctx context.Context, email string) (model.PendingUser, error) {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for GetPendingUser")
	}

	var r0 model.PendingUser
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (model.PendingUser, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) model.PendingUser); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Get(0).(model.PendingUser)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserAuthProviders provides a mock function with given fields: ctx, userUuid
func (_m *IRepository) GetUserAuthProviders(ctx context.Context, userUuid string) ([]string, error) {
	ret := _m.Called(ctx, userUuid)

	if len(ret) == 0 {
		panic("no return value specified for GetUserAuthProviders")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) ([]string, error)); ok {
		return rf(ctx, userUuid)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) []string); ok {
		r0 = rf(ctx, userUuid)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, userUuid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserByEmail provides a mock function with given fields: ctx, email
func (_m *IRepository) GetUserByEmail(ctx context.Context, email string) (model.User, error) {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for GetUserByEmail")
	}

	var r0 model.User
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (model.User, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) model.User); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Get(0).(model.User)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertRefreshToken provides a mock function with given fields: ctx, userUuid, refreshToken, clientIp
func (_m *IRepository) InsertRefreshToken(ctx context.Context, userUuid string, refreshToken string, clientIp string) error {
	ret := _m.Called(ctx, userUuid, refreshToken, clientIp)

	if len(ret) == 0 {
		panic("no return value specified for InsertRefreshToken")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, userUuid, refreshToken, clientIp)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateRefreshToken provides a mock function with given fields: ctx, userUuid, oldRefreshToken, newRefreshToken
func (_m *IRepository) UpdateRefreshToken(ctx context.Context, userUuid string, oldRefreshToken string, newRefreshToken string) error {
	ret := _m.Called(ctx, userUuid, oldRefreshToken, newRefreshToken)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRefreshToken")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) error); ok {
		r0 = rf(ctx, userUuid, oldRefreshToken, newRefreshToken)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateUserPassword provides a mock function with given fields: ctx, uuid, passwordHash
func (_m *IRepository) UpdateUserPassword(ctx context.Context, uuid string, passwordHash string) error {
	ret := _m.Called(ctx, uuid, passwordHash)

	if len(ret) == 0 {
		panic("no return value specified for UpdateUserPassword")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, uuid, passwordHash)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpsertPasswordResetToken provides a mock function with given fields: ctx, userUuid, token, expiresAt
func (_m *IRepository) UpsertPasswordResetToken(ctx context.Context, userUuid string, token string, expiresAt time.Time) error {
	ret := _m.Called(ctx, userUuid, token, expiresAt)

	if len(ret) == 0 {
		panic("no return value specified for UpsertPasswordResetToken")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, time.Time) error); ok {
		r0 = rf(ctx, userUuid, token, expiresAt)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpsertPendingUser provides a mock function with given fields: ctx, email, passwordHash, code, codeExpiresAt
func (_m *IRepository) UpsertPendingUser(ctx context.Context, email string, passwordHash string, code int, codeExpiresAt time.Time) error {
	ret := _m.Called(ctx, email, passwordHash, code, codeExpiresAt)

	if len(ret) == 0 {
		panic("no return value specified for UpsertPendingUser")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, int, time.Time) error); ok {
		r0 = rf(ctx, email, passwordHash, code, codeExpiresAt)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewIRepository creates a new instance of IRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewIRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *IRepository {
	mock := &IRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
