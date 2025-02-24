CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wshadow -D_GLIBCXX_DEBUG

.PHONY: all clean
all: logger logger.so

logger: logger_monitor.cpp
	$(CXX) $(CXXFLAGS) -fPIC logger_monitor.cpp -o logger 

logger.so: logger_so.cpp
	$(CXX) $(CXXFLAGS) -ldl -shared -fPIC logger_so.cpp -o logger.so

clean:
	rm logger
	rm logger.so
	rm -rf *.log
