CC:=gcc
CFLAGS:= \
	-ansi \
	-Wno-long-long \
	-Wall \
	-Wextra \
	-Werror \
	-O2

SRCS:=main.c aes.c sha256.c pkcs7.c
OBJS:=$(addsuffix .o,$(basename $(SRCS)))
TARGET:=parallel-aes

.PHONY: all clean
.SUFFIXES: .o .c

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJS) $(TARGET)

