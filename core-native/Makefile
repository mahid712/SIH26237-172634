CC = C:/MinGW/bin/gcc.exe
CXX = C:/MinGW/bin/g++.exe
CFLAGS = -Wall -O2 -Iinclude
CXXFLAGS = -Wall -O2 -Iinclude -std=c++11

SRCS_C = src/sha256.c src/hkdf.c src/aes_gcm.c src/pqc_kem.c src/keyring.c
SRCS_CPP = src/watermark.cpp src/ledger.cpp src/cli_main.cpp

OBJS_C = $(SRCS_C:.c=.o)
OBJS_CPP = $(SRCS_CPP:.cpp=.o)

TARGET = ../offline_core.exe
STATIC_LIB = ../liboffline_core.a

all: $(TARGET) $(STATIC_LIB)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(TARGET): $(OBJS_C) $(OBJS_CPP)
	$(CXX) $(OBJS_C) $(OBJS_CPP) -o $(TARGET) -static

$(STATIC_LIB): $(OBJS_C) src/watermark.o src/ledger.o
	ar rcs $(STATIC_LIB) $(OBJS_C) src/watermark.o src/ledger.o

clean:
	rm -f src/*.o $(TARGET) $(STATIC_LIB)
