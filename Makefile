#makefile for project 2 works both in linux and unix system now
CFLAGS = -Wall -Wextra -pedantic -std=c11 -g
LDFLAGS = -lpcap
CC = gcc

all: tcp_analyzer

tcp_analyzer: tcp_analyzer.o
	$(CC) $(CFLAGS) -o tcp_analyzer tcp_analyzer.o $(LDFLAGS)

clean:
	-rm -rf *.o tcp_analyzer.dSYM tcp_analyzer
