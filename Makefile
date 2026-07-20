TARGET = btfree
OBJS = src/main.o

PSP_FW_VERSION = 660
BUILD_PRX = 1

USE_KERNEL_LIBC = 1
USE_KERNEL_LIBS = 1

LIBS = -lpspsystemctrl_kernel

CFLAGS = -O2 -G0 -Wall -fno-pic
ASFLAGS = $(CFLAGS)

PSPSDK = $(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build_prx.mak
