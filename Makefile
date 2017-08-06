all: send_arp

send_arp: send_arp.h send_arp.c
	gcc -o send_arp send_arp.c -lpcap

clean:
	rm send_arp.*
