/*cap_open_live - open a device for capturing  

* link: http://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
*/
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define MAXBYTES2CAPTURE 3096

char errbuf[PCAP_ERRBUF_SIZE];
char *device;
int snaplen;
pcap_t *handle; 
struct pcap_pkthdr packet_header;
struct ether_header *eptr;
const u_char *packet;
/****************/
pcap_t *descr = NULL; 
int datalink;
int pcom;



int main(int argc, char **argv){
	/**device look-up*/
	device = pcap_lookupdev(errbuf);
	if(device==NULL){
		printf("no ethernet or network is connected %s\n", errbuf);
		return 1;
	}
	printf("Device Name: %s\n",device);
	
	/*pcap datalink(pcap_t *p) type findings*/
	
	datalink = pcap_datalink(handle);
	printf("datalink description: %d\n 1 means LINKTYPE_ETHERNET\n", datalink);
	
/*snaplen: specifies the snapshot length to be set on the handle.
promisc: specifies if the interface is to be put into promiscuous mode.
to_ms: specifies the packet buffer timeout in milliseconds.
for more info: http://www.tcpdump.org/manpages/pcap.3pcap.html
Open a source device to read packets from.
- device is the physical device (defaults to "any")
- snaplen is the size to capture, where 0 means max possible (defaults to 0)
- promisc is whether to set the device into promiscuous mode (default is false)
- timeout is the timeout for reads in seconds (default is 0, return if no packets available)
*/
	while(packet!=-1){
	handle = pcap_open_live(device, MAXBYTES2CAPTURE , 0, 10000, errbuf);
	
	if(handle== NULL)
	{
		printf("error occured to capture %s \n", errbuf);
		return 1;
	}
	
	
	 /* Attempt to capture one packet. If there is no network traffic
      and the timeout is reached, it will return NULL */
    
		packet = pcap_next(handle, &packet_header);
		printf("packets: %s\n", packet);
	}
	if (packet == NULL) {
        printf("No packet found.\n");
        return 1;
	}
	
	
	

    
	
return 0;
}
