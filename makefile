LDLIBS += -lpcap

all: pcap-test2

pcap-test: pcap-test2.c

clean:
	rm -f pcap-test2 *.o
