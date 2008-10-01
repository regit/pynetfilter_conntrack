CC=gcc
CFLAGS=-Wall -Wextra -Werror -ggdb -O0 -fPIC -shared -Wall -Wextra -Wextra $(shell python-config --cflags)
LIBS=$(shell python-config --libs) -lnetfilter_conntrack
LIBRARY=cnetfilter_conntrack.so
SOURCES=dump.c dump.h filter.c filter.h module.c serialize.c

$(LIBRARY): $(SOURCES)
	$(CC) -o $@ $(SOURCES) $(CFLAGS) $(LIBS)

clean:
	rm -f $(LIBRARY)
