all : arp_spoofing

arp_spoofing: main.o
	g++ -g -o arp_spoofing main.o -lpcap -lpthread

main.o:
	g++ -g -c -o main.o main.cpp -lpthread

clean:
	rm -f send_arp
	rm -f *.o
