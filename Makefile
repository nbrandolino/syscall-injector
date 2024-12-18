CC = gcc
CFLAGS = -Wall -O0 -s
SRCS = inject.c
TARGET = inject
DESTDIR = /usr/bin/


all:
	$(CC) $(SRCS) $(CFLAGS) -o $(TARGET)
install:
	@cp -p $(TARGET) $(DESTDIR)$(TARGET)
uninstall:
	@rm -rf $(DESTDIR)$(TARGET)
