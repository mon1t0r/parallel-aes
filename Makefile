CC:=gcc
CFLAGS:= \
	-ansi \
	-Wno-long-long \
	-Wall \
	-Wextra \
	-Werror \
	-O2

CXX:=g++
CXXFLAGS:= \
	-ansi \
	-Wall \
	-Wextra \
	-Werror \
	-O2

SRCS_CC:=main.c aes.c sha256.c pkcs7.c
SRCS_CXX:=main.cpp
TARGET:=parallel-aes

OBJS_CC:=$(addsuffix .o,$(basename $(SRCS_CC)))
OBJS_CXX:=$(addsuffix .o,$(basename $(SRCS_CXX)))

.PHONY: all clean
.SUFFIXES: .o .c .cpp

all: $(TARGET)

$(TARGET): $(OBJS_CXX) $(OBJS_CC)
	$(CXX) $(CXXFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJS_CC) $(OBJS_CXX) $(TARGET)

