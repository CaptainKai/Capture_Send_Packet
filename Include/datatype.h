/**
* @file         datatype.h
* @brief        total data structure
* @details      using the self-defined basic data type to build data structure
* @author       KaiLi
* @date         2018年3月13日10:20:19
* @version      A001
* @par History:
*   version: author, date, desc\n
*/

#ifndef DATATYPE_H_INCLUDED
#define DATATYPE_H_INCLUDED
#define ARP_FRAME 0x0806 ///< Ethernet "type" : means ARP packet
#define IPV4_FRAME 0x0800///< Ethernet "type" : IPV4 ARP packet
#define IPV6_FRAME 0x86DD///< Ethernet "type" : IPV6 ARP packet

#define ICMP_HFRAME 0x01    ///< IPV4 "flag" : means ICMP packet
#define IGMP_HFRAME 0x02    ///< IPV4 "flag" : means IGMP packet
#define TCP_HFRAME 0x06 ///< IPV4 "flag" : means TCP packet
#define EGP_HFRAME 0x08 ///< IPV4 "flag" : means EGP packet
#define UDP_HFRAME 0x11 ///< IPV4 "flag" : means UDP packet
#define IPV6_HFRAME 0x29///< IPV4 "flag" : means IPV6 packet
#define OSPF_HFRAME 0x59///< IPV4 "flag" : means OSPF packet



typedef unsigned short int hword;   ///< 16 bits. byte ( the 8 bits ) has been defined



typedef unsigned long int word;     ///< 32 bits
/**
 * MAC address structure
 * 6 bytes
 */
typedef struct MAC_addr
{
    byte addr1;
    byte addr2;
    byte addr3;
    byte addr4;
    byte addr5;
    byte addr6;
}MAC_addr;
/**
 * IP address structure
 * 4 bytes
 */
typedef struct IP_addr
{
    byte addr1;
    byte addr2;
    byte addr3;
    byte addr4;
}IP_addr;
#endif // DATATYPE_H_INCLUDED

