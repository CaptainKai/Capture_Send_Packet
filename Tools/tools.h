#ifndef TOOLS_H_INCLUDED
#define TOOLS_H_INCLUDED
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <winsock2.h>
#include <arp.h>
#include <Ethernet.h>
#include <ip.h>
#include <datatype.h>
#include <tcp.h>
bool findDevice( pcap_if_t **alldevs, pcap_if_t **d );
bool filter( pcap_if_t **alldevs, pcap_t **adhandle, u_int netmask);
void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);
void printD(pcap_if_t * d, FILE * file);
void printE( Ethernet * e, FILE * file );
void printM( MAC_addr Maddr, FILE * file);
void printA( const u_char * pkt_data );
void printIP4( const u_char * pkt_data );
void printIP6( const u_char * pkt_data );
void printI( IP_addr  iaddr, FILE * file );
void printT(const u_char * pkt_data, FILE * file );
void sendTCP( pcap_t * fp );
void sendARP( pcap_t * fp );
void sendIP( pcap_t * fp );
#endif // TOOLS_H_INCLUDED
