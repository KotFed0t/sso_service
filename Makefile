gen-mocks:
	docker run --rm -v "$(CURDIR):/src" -w /src vektra/mockery --all

run-tests:
	docker build -f Dockerfile.testing -t app-test . && docker run --rm app-test