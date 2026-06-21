CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -fPIC -shared -static-libstdc++

all: libvigenere.so

libvigenere.so: plugin.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f libvigenere.so

install: all
	cp libvigenere.so ../../