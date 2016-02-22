#makefile for project 2 works both in linux and unix system now
CFLAGS = -Wall -Wextra -pedantic -std=gnu11 -g
LDFLAGS = -lpcap
CC = gcc

all: tcp_analyzer

tcp_analyzer: util.o tcp_analyzer.o
	$(CC) $(CFLAGS) -o tcp_analyzer tcp_analyzer.o util.o $(LDFLAGS)

util.o: util.c
	$(CC) $(CFLAGS) -c util.c

clean:
	-rm -rf *.o tcp_analyzer.dSYM tcp_analyzer
