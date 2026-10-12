CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LIBS = -lm

SRCS = main_puf_demo.c rlwe_puf_auth.c puf_optimized.c puf_timing_measured.c rlwe_core.c ntt.c sha_portable.c
OBJS = $(SRCS:.c=.o)
TARGET = rlwe_puf_auth_demo

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
