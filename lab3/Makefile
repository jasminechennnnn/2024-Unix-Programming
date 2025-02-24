
CC		= gcc
CFLAGS	= -Wall -g -D_GNU_SOURCE -fPIC
LDFLAGS = -lunwind -lunwind-$(shell uname -m)
PROGS	= libsolver.so

all: $(PROGS)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

# maze: maze.o libmaze.so
# 	$(CC) -o $@ $^ $(LDFLAGS)

# libmaze.so: libmaze_dummy.o
# 	$(CC) -o $@ -shared $^ $(LDFLAGS)

libsolver.so: libsolver.o
	$(CC) -o $@ -shared $^ $(LDFLAGS) 

test:
	LD_LIBRARY_PATH=`pwd` LD_PRELOAD=./libsolver.so ./maze

run:
	LD_LIBRARY_PATH=`pwd` ./maze

cleanup:
	rm -f *.o

clean:
	rm -f $(PROGS) *.o
	rm -rf __pycache__

