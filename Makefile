CC = gcc
CFLAGS = -Wall -O0 -s
SRCS = syscall-inject.c
TARGET = syscall-inject
DESTDIR = /usr/bin/


all:
	$(CC) $(SRCS) $(CFLAGS) -o $(TARGET)
static:
	$(CC) $(SRCS) $(CFLAGS) -static -o $(TARGET)
install:
	@cp -p $(TARGET) $(DESTDIR)$(TARGET)
uninstall:
	@rm -rf $(DESTDIR)$(TARGET)
clean:
	@rm -rf $(TARGET)
