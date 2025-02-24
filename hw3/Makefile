all: sdb

sdb: sdb.cpp
	g++ -std=c++20 -Wall -Wextra -Wshadow -D_GLIBCXX_DEBUG sdb.cpp -lcapstone -o sdb 

clean:
	rm -f sdb

.PHONY: all clean
