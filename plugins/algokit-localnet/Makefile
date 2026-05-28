.PHONY: all build run clean checksum

PLUGIN := algokit-localnet
ROOT := ../..
CHECKSUM_TOOL := $(ROOT)/bin/applugin-checksum

all: build

build:
	CGO_ENABLED=0 go build -trimpath -o $(PLUGIN) ./$(PLUGIN).go

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
