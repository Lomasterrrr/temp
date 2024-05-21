CC := gcc
LIBPCAP_DIR := ../libpcap
CFLAGS := -Wall -O3 -I../build -g -I$(LIBPCAP_DIR)
LDFLAGS := -L../build -Wl,-rpath,../build
LDLIBS := -lncsock

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
PROGS := $(SRCS:.c=)

all: $(PROGS)

%: %.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c  -o $@ $<

clean:
	rm -f $(PROGS) $(OBJS)
