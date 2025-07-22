APPLICATION = profiling

BOARD ?= nrf52840dk

PROJECT_BASE ?= $(CURDIR)/../..
RIOTBASE ?= $(PROJECT_BASE)/RIOT

EXTERNAL_MODULE_DIRS += $(PROJECT_BASE)/modules
EXTERNAL_PKG_DIRS += $(PROJECT_BASE)/modules



# Custom stack size
CFLAGS += -g0


CFLAGS += -Wno-unused-parameter

USEMODULE += ml-kem-512
INCLUDES += -I$(PROJECT_BASE)/modules/ml-kem-512/include

USEMODULE += xtimer
USEMODULE += periph_cpuid
USEMODULE += kem-dsa-common
USEMODULE += random



include $(RIOTBASE)/Makefile.include
