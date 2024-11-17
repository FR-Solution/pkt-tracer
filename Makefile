export GOSUMDB=off
export GO111MODULE=on

$(value $(shell [ ! -d "$(CURDIR)/bin" ] && mkdir -p "$(CURDIR)/bin"))
export GOBIN=$(CURDIR)/bin
DEPLOY:=$(CURDIR)/deploy

GO?=$(shell which go)
GIT_TAG:=$(shell git describe --exact-match --abbrev=0 --tags 2> /dev/null)
GIT_HASH:=$(shell git log --format="%h" -n 1 2> /dev/null)
GIT_BRANCH:=$(shell git branch 2> /dev/null | grep '*' | cut -f2 -d' ')
GO_VERSION:=$(shell go version | sed -E 's/.* go(.*) .*/\1/g')
BUILD_TS:=$(shell date +%FT%T%z)
VERSION:=$(shell cat ./VERSION 2> /dev/null | sed -n "1p")

PROJECT:=H-BF
APP?=pkt-tracer
APP_NAME?=$(PROJECT)/$(APP)
APP_VERSION:=$(if $(VERSION),$(VERSION),$(if $(GIT_TAG),$(GIT_TAG),$(GIT_BRANCH)))

.NOTPARALLEL:

.PHONY: help
help: ##display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

GOLANGCI_BIN:=$(GOBIN)/golangci-lint
GOLANGCI_REPO=https://github.com/golangci/golangci-lint
GOLANGCI_LATEST_VERSION:= $(shell git ls-remote --tags --refs --sort='v:refname' $(GOLANGCI_REPO)|tail -1|egrep -o "v[0-9]+.*")
ifneq ($(wildcard $(GOLANGCI_BIN)),)
	GOLANGCI_CUR_VERSION=v$(shell $(GOLANGCI_BIN) --version|sed -E 's/.*version (.*) built.*/\1/g')	
else
	GOLANGCI_CUR_VERSION=
endif

.PHONY: .install-linter
.install-linter:
ifeq ($(filter $(GOLANGCI_CUR_VERSION), $(GOLANGCI_LATEST_VERSION)),)
	$(info Installing GOLANGCI-LINT $(GOLANGCI_LATEST_VERSION)...)
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) $(GOLANGCI_LATEST_VERSION)
	@chmod +x $(GOLANGCI_BIN)
else
	@echo 1 >/dev/null
endif

.PHONY: lint
lint: ##run full lint
	@echo full lint... && \
	$(MAKE) .install-linter && \
	$(GOLANGCI_BIN) cache clean && \
	$(GOLANGCI_BIN) run --timeout=120s --config=$(CURDIR)/.golangci.yaml -v $(CURDIR)/... &&\
	echo -=OK=-

.PHONY: go-deps
go-deps: ##install golang dependencies
	@echo check go modules dependencies ... && \
	$(GO) mod tidy && \
 	$(GO) mod vendor && \
	$(GO) mod verify && \
	echo -=OK=-

.PHONY: test
test: ##run tests
	@echo running tests... && \
	$(GO) clean -testcache && \
	$(GO) test -v -race ./... && \
	echo -=OK=-

platform?=$(shell $(GO) env GOOS)/$(shell $(GO) env GOARCH)
os?=$(strip $(filter linux darwin,$(word 1,$(subst /, ,$(platform)))))
arch?=$(strip $(filter amd64 arm64,$(word 2,$(subst /, ,$(platform)))))
OUT?=$(CURDIR)/bin/$(APP)

APP_IDENTITY?=github.com/H-BF/corlib/app/identity
LDFLAGS?=-X '$(APP_IDENTITY).Name=$(APP_NAME)'\
         -X '$(APP_IDENTITY).Version=$(APP_VERSION)'\
         -X '$(APP_IDENTITY).BuildTS=$(BUILD_TS)'\
         -X '$(APP_IDENTITY).BuildBranch=$(GIT_BRANCH)'\
         -X '$(APP_IDENTITY).BuildHash=$(GIT_HASH)'\
         -X '$(APP_IDENTITY).BuildTag=$(GIT_TAG)'\

.PHONY: pkt-tracer
pkt-tracer: ##build pkt-tracer. Usage: make pkt-tracer [platform=linux/<amd64|arm64>]
ifeq ($(filter amd64 arm64,$(arch)),)
	$(error arch=$(arch) but must be in [amd64|arm64])
endif
ifneq ('$(os)','linux')
	@$(MAKE) $@ os=linux
else
	@$(MAKE) go-deps && \
	echo build '$(APP)' for OS/ARCH='$(os)'/'$(arch)' ... && \
	echo into '$(OUT)' && \
	env GOOS=$(os) GOARCH=$(arch) CGO_ENABLED=0 \
	$(GO) build -ldflags="$(LDFLAGS)" -o $(OUT) $(CURDIR)/cmd/$(APP) &&\
	echo -=OK=-
endif	

.PHONY: trace-hub
trace-hub: | go-deps ##build trace-hub. Usage: make trace-hub [os=<linux|darwin>] [arch=<amd64|arm64>]
trace-hub: APP=trace-hub
trace-hub: OUT=$(CURDIR)/bin/$(APP)
trace-hub:
ifeq ($(filter linux darwin,$(os)),)
	$(error os=$(os) but must be in [linux|darwin])
endif
ifeq ($(filter amd64 arm64,$(arch)),)
	$(error arch=$(arch) but must be in [amd64|arm64])
endif
	@echo build '$(APP)' for OS/ARCH='$(os)'/'$(arch)' ... && \
	echo into '$(OUT)' && \
	env GOOS=$(os) GOARCH=$(arch) CGO_ENABLED=0 \
	$(GO) build -ldflags="$(LDFLAGS)" -o $(OUT) $(CURDIR)/cmd/$(APP) &&\
	echo -=OK=-

.PHONY: visor-cli
visor-cli: | go-deps ##build visor-cli. Usage: make visor-cli [os=<linux|darwin>] [arch=<amd64|arm64>]
visor-cli: APP=visor-cli
visor-cli: OUT=$(CURDIR)/bin/$(APP)
visor-cli:
ifeq ($(filter linux darwin,$(os)),)
	$(error os=$(os) but must be in [linux|darwin])
endif
ifeq ($(filter amd64 arm64,$(arch)),)
	$(error arch=$(arch) but must be in [amd64|arm64])
endif
	@echo build '$(APP)' for OS/ARCH='$(os)'/'$(arch)' ... && \
	echo into '$(OUT)' && \
	env GOOS=$(os) GOARCH=$(arch) CGO_ENABLED=0 \
	$(GO) build -ldflags="$(LDFLAGS)" -o $(OUT) $(CURDIR)/cmd/$(APP) &&\
	echo -=OK=-

.PHONY: visor-ui
visor-ui: | go-deps ##build visor-ui. Usage: make visor-ui [os=<linux|darwin>] [arch=<amd64|arm64>]
visor-ui: APP=visor-ui
visor-ui: OUT=$(CURDIR)/bin/$(APP)
visor-ui:
ifeq ($(filter linux darwin,$(os)),)
	$(error os=$(os) but must be in [linux|darwin])
endif
ifeq ($(filter amd64 arm64,$(arch)),)
	$(error arch=$(arch) but must be in [amd64|arm64])
endif
	@echo build '$(APP)' for OS/ARCH='$(os)'/'$(arch)' ... && \
	echo into '$(OUT)' && \
	env GOOS=$(os) GOARCH=$(arch) CGO_ENABLED=0 \
	$(GO) build -ldflags="$(LDFLAGS)" -o $(OUT) $(CURDIR)/cmd/$(APP) &&\
	echo -=OK=-

.PHONY: .install-grpc-plugins
.install-grpc-plugins:
ifeq ($(wildcard $(GOBIN)/protoc-gen-go),)
	@echo Install \"protoc-gen-go\"
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go
endif
ifeq ($(wildcard $(GOBIN)/protoc-gen-go-grpc),)
	@echo Install \"protoc-gen-go-grpc\"
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc
endif
	@echo 0 > /dev/null

proto_dirs := tracehub
.PHONY: generate-api
generate-api: | .install-grpc-plugins ##generate-api. generate API code from proto files
	@(\
	apis=$(CURDIR)/api && \
	dest=$(CURDIR)/pkg/api && \
	PATH=$(PATH):$(GOBIN):/usr/include:/usr/local/include && \
	rm -rf $$dest 2>/dev/null && \
	mkdir -p $$dest && \
	echo generating API in \"$$dest\" ... && \
	for p in $(proto_dirs); do \
		for v in $$apis/$$p/*.proto; do \
			echo  "  - " \"$$p/$$(basename $$v)\" ;\
			protoc \
				--go_opt=paths=source_relative \
				--go-grpc_opt=paths=source_relative \
				--go_out $$dest \
				--go-grpc_out $$dest \
				--proto_path=$$apis \
				"$$v" ||\
			exit 1;\
		done; \
	done; \
	echo -=OK=- ;\
	)

GOOSE_REPO:=https://github.com/pressly/goose
GOOSE_LATEST_VERSION:= $(shell git ls-remote --tags --refs --sort='v:refname' $(GOOSE_REPO)|tail -1|egrep -o "v[0-9]+.*")
GOOSE:=$(GOBIN)/goose
ifneq ($(wildcard $(GOOSE)),)
	GOOSE_CUR_VERSION?=$(shell $(GOOSE) -version|egrep -o "v[0-9\.]+")	
else
	GOOSE_CUR_VERSION?=
endif
.PHONY: .install-goose
.install-goose: 
ifeq ($(filter $(GOOSE_CUR_VERSION), $(GOOSE_LATEST_VERSION)),)
	@echo installing \'goose\' $(GOOSE_LATEST_VERSION) util... && \
	GOBIN=$(GOBIN) $(GO) install github.com/pressly/goose/v3/cmd/goose@$(GOOSE_LATEST_VERSION)
else
	@echo >/dev/null
endif

# example CLICK_MIGRATIONS="tcp://root:qwerty@localhost:19000/swarm?max_execution_time=60&dial_timeout=10s&client_info_product=trace-hub/0.0.1&compress=lz4&block_buffer_size=10&max_compression_buffer=10240&skip_verify=true"
CLICK_MIGRATIONS?=$(CURDIR)/internal/registry/clickhouse/scripts/migrations
CLICKHOUSE_URI?=
.PHONY: click-migrations
click-migrations: ##run pkt-tracer Clickhouse migrations
ifneq ($(CLICKHOUSE_URI),)
	@$(MAKE) .install-goose && \
	cd $(CLICK_MIGRATIONS) && \
	$(GOOSE) clickhouse $(CLICKHOUSE_URI) up
else
	$(error need define CLICKHOUSE_URI environment variable)
endif


MOCKERY_REPO:=https://github.com/vektra/mockery
MOCKERY_LATEST_VERSION:= $(shell git ls-remote --tags --refs --sort='v:refname' $(MOCKERY_REPO)|egrep -o "v[0-9]+.*"|grep -v "alpha"|tail -1)
MOCKERY:=$(GOBIN)/mockery
ifneq ($(wildcard $(MOCKERY)),)
	MOCKERY_CUR_VERSION?=$(shell $(MOCKERY) --version|egrep -o "v[0-9]+.*")
else
	MOCKERY_CUR_VERSION?=
endif
.PHONY: .install-mockery
.install-mockery:
ifeq ($(filter $(MOCKERY_CUR_VERSION), $(MOCKERY_LATEST_VERSION)),)
	@echo installing \'mockery\' $(MOCKERY_LATEST_VERSION) util... && \
	GOBIN=$(GOBIN) $(GO) install github.com/vektra/mockery/v2@$(GOOSE_LATEST_VERSION)
else
	@echo >/dev/null
endif

.PHONY:
generate:
	@echo executing go generate for all subdirs ... && \
	 $(GO) generate ./... && \
	echo -=OK=-


.PHONY: clean
clean: ##clean project
	rm -rf $(CURDIR)/bin/
	rm -rf $(CURDIR)/vendor/
