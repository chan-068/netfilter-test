all: netfilter-test

netfilter-test: netfilter-test.c
	gcc netfilter-test.c -o netfilter-test -lnetfilter_queue

clean:
	rm -f netfilter-test

.PHONY: all clean