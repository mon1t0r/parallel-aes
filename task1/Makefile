CC:=gcc
CFLAGS:= \
	-ansi \
	-Wno-long-long \
	-Wall \
	-Wextra \
	-Werror \
	-O2

ZIP_AR:=zadanie1.zip
# XXX: Needed for task checking system, this is NOT an a PE file
TARGET:=zadanie1.exe
SRCS:=zadanie1.c

OBJS:=$(addsuffix .o,$(basename $(SRCS)))

.PHONY: all zip compile clean
.SUFFIXES: .o .c

# All target
all: $(TARGET)

# Zip archive target
zip: $(ZIP_AR)

# Target for task checking system
compile: $(TARGET)

$(ZIP_AR): $(SRCS) Makefile
	zip -q $@ $^

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJS) $(TARGET) $(ZIP_AR)

