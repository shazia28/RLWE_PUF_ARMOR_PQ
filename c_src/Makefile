CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -fstack-usage
LDFLAGS = -Wl,-Map=armor_pq.map
LIBS = -lm

SRCS = main_puf_demo.c rlwe_puf_auth.c puf_optimized.c puf_timing_measured.c rlwe_core.c ntt.c sha_portable.c
OBJS = $(SRCS:.c=.o)
TARGET = rlwe_puf_auth_demo

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LIBS)
	size $(OBJS) $(TARGET) > memory_footprint_report.txt

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) *.su armor_pq.map memory_footprint_report.txt

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
