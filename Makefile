CFLAGS= -O2 -pipe -march=native -std=c99 -pedantic -Wall -Wextra -D_GNU_SOURCE -D_FORTIFY_SOURCE=2
CC=gcc

safeguard : safeguard.c
	$(CC) $(CFLAGS) -o safeguard safeguard.c
clean :
	rm safeguard
debug :
	$(CC) $(CFLAGS) -o safeguard safeguard.c -g
