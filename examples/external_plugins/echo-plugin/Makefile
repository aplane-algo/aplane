.PHONY: all build run clean checksum

PLUGIN := echo-plugin
ROOT := ../../..
CHECKSUM_TOOL := $(ROOT)/bin/applugin-checksum

all: build

build:
	go build -o $(PLUGIN) ./echo-plugin.go

run: build
	./$(PLUGIN)

clean:
	rm -f $(PLUGIN)

checksum:
	@test -x "$(CHECKSUM_TOOL)" || { \
		echo "Missing $(CHECKSUM_TOOL). Build it from repo root with: make applugin-checksum"; \
		exit 1; \
	}
	"$(CHECKSUM_TOOL)" .
