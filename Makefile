CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -lm -lz -L/opt/homebrew/opt/openssl@3/lib -lcrypto

SRCS = main.c stego.c image.c png.c
OBJS = $(SRCS:.c=.o)
TARGET = stego
TEST = test_stego

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

$(TEST): test_stego.c stego.o image.o png.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: $(TARGET) $(TEST)
	./$(TEST)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(TEST) test.png output.png test_data.txt extracted.txt 