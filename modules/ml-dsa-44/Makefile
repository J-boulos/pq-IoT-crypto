MODULE := ml-dsa-44

SRC += src/ntt.c 
SRC += src/packing.c 
SRC += src/poly.c 
SRC += src/polyvec.c 
SRC += src/reduce.c 
SRC += src/rounding.c 
SRC += src/sign.c 
SRC += src/symmetric-shake.c


CFLAGS += -O3 -Wall -Wextra -Wpedantic -Werror \
          -Wmissing-prototypes -Wredundant-decls -std=c99 

include $(RIOTBASE)/Makefile.base
