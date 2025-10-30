CXX = g++
CXXFLAGS = -std=c++17 -g -O0 -Wall -Wextra -I/opt/homebrew/include -Iinclude
LDFLAGS = -L/opt/homebrew/lib -lnetsnmp -lnetsnmpagent -lnetsnmpmibs
SRC_DIR = src
SRCS = $(SRC_DIR)/main.cpp $(SRC_DIR)/snmp.cpp $(SRC_DIR)/otel.cpp $(SRC_DIR)/utils.cpp
OBJS = $(SRCS:.cpp=.o)
TARGET = snmp2otel

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

run: all
	./$(TARGET)

test: $(SRC_DIR)/test/test_snmp.cpp snmp2otel
	$(CXX) $(CXXFLAGS) $(SRC_DIR)/tests.cpp $(SRC_DIR)/snmp.cpp $(SRC_DIR)/utils.cpp -o run_tests $(LDFLAGS)
	./run_tests

clean:
	rm -f $(TARGET) run_tests $(OBJS)
