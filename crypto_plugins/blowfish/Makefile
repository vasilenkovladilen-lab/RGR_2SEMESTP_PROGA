CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -fPIC -shared
LDFLAGS = -lssl -lcrypto

all: libblowfish.so

libblowfish.so: plugin.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f libblowfish.so

install: all
	cp libblowfish.so ../../
