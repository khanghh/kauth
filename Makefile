.DEFAULT_GOAL := kauth

BUILD_DIR=$(CURDIR)/build/bin
COMMIT=$(shell git rev-parse HEAD)
DATE=$(shell git show -s --format=%cI HEAD)
TAG=$(shell git describe --tags --always --dirty)

LDFLAGS=-ldflags "-w -s -X 'main.gitCommit=$(COMMIT)' -X 'main.gitDate=$(DATE)' -X 'main.gitTag=$(TAG)'"

kauth:
	@echo "Building target: $@" 
	go run ./build/tools/gen_query/main.go
	go build $(LDFLAGS) -o $(BUILD_DIR)/$@ $(CURDIR)
	@echo "Done building."

build-docker:
	@echo "Building Docker image kauth:latest" 
	docker build --rm --progress=plain \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg GIT_DATE=$(GIT_DATE) \
		--build-arg GIT_TAG=$(GIT_TAG) \
		-t kauth:latest \
		-f Dockerfile .
	@echo "Done building."

clean:
	@rm -rf $(BUILD_DIR)/*

all: kauth
