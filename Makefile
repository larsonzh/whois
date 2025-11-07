# Makefile for whois client

CC ?= gcc
# Allow callers to append extra flags without complex quoting on Windows/SSH
CFLAGS ?= -O2 -Wall -Wextra -std=c11
# Add include path for modularized headers and allow external extra flags
CFLAGS += -Iinclude $(CFLAGS_EXTRA)

# CI-only stricter warnings (does not affect local builds)
ifneq (,$(filter 1 true TRUE yes YES,$(CI)))
CFLAGS += -Werror=sign-compare -Werror=format
endif
LDFLAGS ?=
LIBS ?= -pthread
TARGET ?= whois-client

# Support single-file and multi-file layouts transparently
SRCS := $(wildcard src/*.c) $(wildcard src/*/*.c)
OBJS := $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Optional static build (depends on toolchain and libc availability)
STATIC_TARGET ?= $(TARGET).static
static: $(STATIC_TARGET)

$(STATIC_TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) -static $(LDFLAGS_EXTRA) $(LIBS)

clean:
	rm -f $(TARGET) $(STATIC_TARGET) $(OBJS)

.PHONY: all clean static
