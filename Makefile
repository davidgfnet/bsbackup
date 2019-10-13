
all:
	g++ -o server server.cc -lcrypto -lssl -lpthread -O2 -std=c++17

