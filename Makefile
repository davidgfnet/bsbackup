
all:
	g++ -o server server.cc -lcrypto -lssl -lpthread -lconfig -O2 -std=c++17 -Wall

