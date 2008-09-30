CC=gcc
CFLAGS=-fPIC -shared -Wall -Wextra -Wextra $(shell python-config --cflags)
LIBS=$(shell python-config --libs) -lnetfilter_conntrack
LIBRARY=cnetfilter_conntrack.so

$(LIBRARY): conntrack.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBS)

clean:
	rm -f $(LIBRARY)
