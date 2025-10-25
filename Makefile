# Simple Makefile for whois client (v3.1.0)

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDFLAGS ?=
LIBS ?= -pthread
TARGET ?= whois-client
SRC := src/whois_client.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LIBS)

# Optional static build (depends on toolchain and libc availability)
STATIC_TARGET ?= $(TARGET).static
static: $(STATIC_TARGET)

$(STATIC_TARGET): $(SRC)
	$(CC) $(CFLAGS) -static -o $@ $(SRC) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)
	rm -f $(STATIC_TARGET)

.PHONY: all clean static
