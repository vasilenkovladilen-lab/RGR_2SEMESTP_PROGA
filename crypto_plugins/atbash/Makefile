CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -fPIC -shared -static-libstdc++

all: libatbash.so

libatbash.so: plugin.cpp
    $(CXX) $(CXXFLAGS) -o $@ $^

clean:
    rm -f libatbash.so

install: all
    cp libatbash.so ../../