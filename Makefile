CC=gcc
CFLAGS+=-O3 -fwrapv -Wall

all:  endiantest

endiantest.o: endiantest.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c endiantest.c

endiantest: endiantest.o 
	$(CC) $(CFLAGS) $(CPPFLAGS) -o endiantest endiantest.o  $(LDFLAGS)

clean:
	rm -f *.o  endiantest

