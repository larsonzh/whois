# Makefile for whois client

CC ?= gcc
# Allow callers to append extra flags without complex quoting on Windows/SSH
CFLAGS ?= -O2 -Wall -Wextra -std=c11
# Version injection: prefer VERSION.txt if present; fallback to literal
WHOIS_VERSION_FILE ?= VERSION.txt
ifeq ($(wildcard $(WHOIS_VERSION_FILE)),)
WHOIS_VERSION ?= 3.2.5
else
WHOIS_VERSION := $(strip $(shell cat $(WHOIS_VERSION_FILE)))
endif

# Add include path for modularized headers and allow external extra flags; inject version macro
CFLAGS += -Iinclude $(CFLAGS_EXTRA) -DWHOIS_VERSION=\"$(WHOIS_VERSION)\"

# Default build profile (can be overridden by OPT_PROFILE=...)
OPT_PROFILE ?= lto

# Optional build profile for startup/size optimization.
# Usage: make OPT_PROFILE=small
ifneq (,$(filter small,$(OPT_PROFILE)))
CFLAGS += -Os -s -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables
LDFLAGS += -Wl,--gc-sections -Wl,--as-needed
endif

# LTO profile: builds on 'small' and enables link-time optimization.
# Usage: make OPT_PROFILE=lto
ifneq (,$(filter lto,$(OPT_PROFILE)))
CFLAGS += -Os -s -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -flto
LDFLAGS += -Wl,--gc-sections -Wl,--as-needed -flto
endif

# CI-only stricter warnings (does not affect local builds)
ifneq (,$(filter 1 true TRUE yes YES,$(CI)))
CFLAGS += -Werror=sign-compare -Werror=format
endif
LDFLAGS ?=
LIBS ?= -pthread
TARGET ?= whois-client

# Support single-file and multi-file layouts transparently
SRCS := $(wildcard src/*.c) $(wildcard src/*/*.c)
# Future modularization: explicit core submodules (net/server/lookup) will live under src/core/
# The wildcard already captures them once added.
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

# Quick lint (host compiler): syntax/type + key warnings as errors, no objects produced
LINT_FLAGS := $(CFLAGS) -Werror=sign-compare -Werror=format -fsyntax-only
lint:
	@echo "[lint] Checking sources with $(CC)"
	@set -e; \
	for f in $(SRCS); do \
		$(CC) $(LINT_FLAGS) $$f; \
	done
	@echo "[lint] OK"
