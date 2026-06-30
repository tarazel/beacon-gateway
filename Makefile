.PHONY: build gateway admin relay run test test-integration tidy docker

build: gateway admin relay

gateway:
	go build -o bin/gateway ./cmd/gateway

admin:
	go build -o bin/beacon-admin ./cmd/admin

relay:
	go build -o bin/relay ./cmd/relay

run: gateway
	./bin/gateway

test:
	go test ./...

# Integration tests need a local DynamoDB (e.g. amazon/dynamodb-local on :8000).
test-integration:
	go test -tags integration ./... -run Integration

tidy:
	go mod tidy

docker:
	docker compose build

# build-RelayFunction is invoked by `sam build` (BuildMethod: makefile) from the
# relay template's CodeUri (repo root). It cross-compiles the Lambda binary as
# `bootstrap` into the SAM artifacts dir for the provided.al2023 arm64 runtime.
.PHONY: build-RelayFunction
build-RelayFunction:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -ldflags="-s -w" -o $(ARTIFACTS_DIR)/bootstrap ./cmd/relay
