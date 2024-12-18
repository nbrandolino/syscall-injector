CC= gcc
CFLAGS= -Wall -O0 -g
SRCS= inject.c
TARGET= inject


$(TARGET): $(SRCS)
	$(CC) $(SRCS) $(CFLAGS) -o $(TARGET)
