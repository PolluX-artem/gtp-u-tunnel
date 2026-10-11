CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -O3 -MMD -MP
LDFLAGS = -pthread

# make SANITIZE=1  ->  debug build with AddressSanitizer + UndefinedBehaviorSanitizer
ifeq ($(SANITIZE),1)
CXXFLAGS = -std=c++20 -Wall -Wextra -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -MMD -MP
LDFLAGS += -fsanitize=address,undefined
endif

TARGET = tun
SRCS = src/tun.cpp src/Upf.cpp src/UeTable.cpp src/ArpTable.cpp
OBJS = $(SRCS:.cpp=.o)
DEPS = $(OBJS:.o=.d)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)

.PHONY: all clean

-include $(DEPS)
