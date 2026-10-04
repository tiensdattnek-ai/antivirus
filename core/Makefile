CXX ?= g++
FLAGS = -O3 -std=c++17 -shared -fPIC -pthread
all:
	$(CXX) $(FLAGS) engine.cpp -o libsentinelx_core.so
clean:
	rm -f libsentinelx_core.so sentinelx_core.dll
