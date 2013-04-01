CFLAGS= -O2 -std=c99 -pedantic -Wextra -Wall
CC=gcc

safeguard : safeguard.c
	$(CC) $(CFLAGS) -o safeguard safeguard.c
clean :
	rm safeguard
debug :
	$(CC) $(CFLAGS) -o safeguard safeguard.c -g
