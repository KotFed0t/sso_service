gen-mocks:
	docker run --rm -v "$(CURDIR):/src" -w /src vektra/mockery --all

run-tests:
	docker build -f Dockerfile.testing -t app-test . && docker run --rm app-test

genproto:
	protoc --go_out=pkg --go-grpc_out=pkg --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative proto/sso/v1/sso.proto

migrate:
	docker run -v "${PWD}/migrations:/migrations" --network host migrate/migrate -path=/migrations/ -database postgres://sso_service:sso_service@localhost:6432/sso_service?sslmode=disable up