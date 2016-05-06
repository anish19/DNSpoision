CC=gcc
CFLAGS=-I.
DEPS = mydump.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

mydump: mydump.o
	gcc -o mydump mydump.o -I. -lpcap

clean:
	rm -f *.o mydump
