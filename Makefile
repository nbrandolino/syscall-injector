CC= gcc
CFLAGS= -Wall -O0 -s
SRCS= inject.c
TARGET= inject


$(TARGET): $(SRCS)
	$(CC) $(SRCS) $(CFLAGS) -o $(TARGET)
