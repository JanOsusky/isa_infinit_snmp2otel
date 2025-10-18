CXX = g++
CXXFLAGS = -std=c++17 -g -O0 -Wall -Wextra
SRC_DIR = src
SRCS = $(SRC_DIR)/main.cpp $(SRC_DIR)/snmp.cpp $(SRC_DIR)/otel.cpp $(SRC_DIR)/utils.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = snmp2otel

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@

run: all
	./$(TARGET)

test: $(SRC_DIR)/tests.cpp snmp2otel
	$(CXX) $(CXXFLAGS) $(SRC_DIR)/tests.cpp $(SRC_DIR)/snmp.cpp $(SRC_DIR)/utils.cpp -o run_tests
	./run_tests

clean:
	rm -f $(TARGET) run_tests *.o
