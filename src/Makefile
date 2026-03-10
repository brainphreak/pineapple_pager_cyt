# Chasing Your Tail — Cross-compilation Makefile
# Target: MIPS 24KEc (mipsel-linux-muslsf), OpenWrt 24.10
#
# Usage (run from project root or src/):
#   make cross          — Build all binaries via Docker
#   make clean          — Remove build artifacts
#   make deploy         — SCP binaries to device

# ---------------------------------------------------------------
# Paths
# ---------------------------------------------------------------
PROJECT_DIR ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST)))..)
SRC_DIR     := $(PROJECT_DIR)/src
BUILD_DIR   := $(PROJECT_DIR)/build
PAYLOAD_DIR := $(PROJECT_DIR)/payload

DEVICE_IP   := 172.16.52.1
DEVICE_PATH := /mmc/root/payloads/user/reconnaissance/cyt

# Docker image with musl MIPS cross-compiler
DOCKER_IMAGE := mipsel-cross:latest
TOOLCHAIN    := /opt/mipsel-linux-muslsf-cross/bin
CC           := $(TOOLCHAIN)/mipsel-linux-muslsf-gcc
STRIP        := $(TOOLCHAIN)/mipsel-linux-muslsf-strip

# ---------------------------------------------------------------
# Compiler flags
# ---------------------------------------------------------------
CFLAGS  := -static -O2 -Wall -Wextra \
            -DSQLITE_THREADSAFE=0 \
            -DSQLITE_DEFAULT_MEMSTATUS=0 \
            -DSQLITE_OMIT_LOAD_EXTENSION \
            -I$(SRC_DIR)

# BLE scanner needs Bluetooth headers (from musl-cross BlueZ)
BLE_CFLAGS := $(CFLAGS) -lbluetooth
# Actually link flags go at the end:
BLE_LDFLAGS := -lbluetooth

# ---------------------------------------------------------------
# Source files
# ---------------------------------------------------------------
SQLITE_SRC  := $(SRC_DIR)/sqlite3.c
DB_SRC      := $(SRC_DIR)/db.c

BLE_SRC     := $(SRC_DIR)/ble_scanner.c $(DB_SRC) $(SQLITE_SRC)
ANA_SRC     := $(SRC_DIR)/analyzer.c    $(DB_SRC) $(SQLITE_SRC)
UI_SRC      := $(SRC_DIR)/cyt_ui.c      $(DB_SRC) $(SQLITE_SRC)
WIFI_SRC    := $(SRC_DIR)/wifi_scanner.c $(DB_SRC) $(SQLITE_SRC)

# ---------------------------------------------------------------
# Output binaries
# ---------------------------------------------------------------
BLE_BIN     := $(BUILD_DIR)/ble_scanner
ANA_BIN     := $(BUILD_DIR)/analyzer
UI_BIN      := $(BUILD_DIR)/cyt_ui
WIFI_BIN    := $(BUILD_DIR)/wifi_scanner

.PHONY: cross clean deploy dirs check-docker

# ---------------------------------------------------------------
# Default target: cross-compile all via Docker
# ---------------------------------------------------------------
cross: check-docker dirs
	docker run --rm \
	    -v "$(PROJECT_DIR):/project" \
	    $(DOCKER_IMAGE) \
	    sh /project/scripts/docker_build.sh

# ---------------------------------------------------------------
# Deploy to device
# ---------------------------------------------------------------
deploy: cross
	@echo "Deploying to $(DEVICE_IP):$(DEVICE_PATH) ..."
	ssh root@$(DEVICE_IP) "mkdir -p $(DEVICE_PATH)/fonts"
	scp $(BUILD_DIR)/ble_scanner   root@$(DEVICE_IP):$(DEVICE_PATH)/ble_scanner
	scp $(BUILD_DIR)/analyzer      root@$(DEVICE_IP):$(DEVICE_PATH)/analyzer
	scp $(BUILD_DIR)/cyt_ui        root@$(DEVICE_IP):$(DEVICE_PATH)/cyt_ui
	-scp $(BUILD_DIR)/wifi_scanner root@$(DEVICE_IP):$(DEVICE_PATH)/wifi_scanner
	scp $(PAYLOAD_DIR)/payload.sh  root@$(DEVICE_IP):$(DEVICE_PATH)/payload.sh
	ssh root@$(DEVICE_IP) "chmod +x $(DEVICE_PATH)/*.sh $(DEVICE_PATH)/ble_scanner $(DEVICE_PATH)/analyzer $(DEVICE_PATH)/cyt_ui $(DEVICE_PATH)/wifi_scanner 2>/dev/null; echo Done"
	@echo "Deploy complete."

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
dirs:
	mkdir -p $(BUILD_DIR)

check-docker:
	@docker inspect $(DOCKER_IMAGE) >/dev/null 2>&1 || \
	  (echo "ERROR: Docker image '$(DOCKER_IMAGE)' not found." && \
	   echo "Build it with: docker build -t mipsel-cross:latest ." && exit 1)

clean:
	rm -f $(BUILD_DIR)/ble_scanner $(BUILD_DIR)/analyzer \
	       $(BUILD_DIR)/cyt_ui $(BUILD_DIR)/wifi_scanner
	@echo "Build artifacts removed."
