MODULE := ml-kem-512

SRC += src/cbd.c
SRC += src/indcpa.c
SRC += src/kem.c
SRC += src/ntt.c
SRC += src/poly.c
SRC += src/polyvec.c
SRC += src/reduce.c
SRC += src/symmetric-shake.c
SRC += src/verify.c

CFLAGS += -O3 -Wall -Wextra -Wpedantic -Werror \
          -Wmissing-prototypes -Wredundant-decls -std=c99 


include $(RIOTBASE)/Makefile.base
