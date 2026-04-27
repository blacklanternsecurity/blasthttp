CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter
LDFLAGS ?=

CURL_CFLAGS := $(shell pkg-config --cflags libcurl)
CURL_LIBS   := $(shell pkg-config --libs libcurl)

BIN_DIR := ../../target/bench

all: $(BIN_DIR)/server $(BIN_DIR)/client-go $(BIN_DIR)/client-c

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/server: server.go | $(BIN_DIR)
	go build -o $@ server.go

$(BIN_DIR)/client-go: client.go | $(BIN_DIR)
	go build -o $@ client.go

$(BIN_DIR)/client-c: client.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $(CURL_CFLAGS) -o $@ client.c $(CURL_LIBS) $(LDFLAGS)

clean:
	rm -f $(BIN_DIR)/server $(BIN_DIR)/client-go $(BIN_DIR)/client-c

.PHONY: all clean
