/**
* @file     arp.h
* @brief    arp head data structure
* @details  ARP data structure without checksum
* @author   KaiLi
* @date     2018年3月13日09:55:29
* @version  A001(no checksum)
* @par History:
*   version: author, date, desc\n
*/
#ifndef ARP_H_INCLUDED
#define ARP_H_INCLUDED
#include <datatype.h>
typedef struct Header_A
{
    hword htype;    ///< hardware type ( 2 bytes )
    hword ptype;    ///< protocol type ( 2 bytes )
    byte   hsize;   ///< hardware address length ( 1 bytes )
    byte   pzise;   ///< protocal address length ( 1 bytes )
    hword opcode;   ///< operator code ( 2 bytes )
    MAC_addr sMAC;  ///< sender MAC address ( 6 bytes )
    IP_addr  sIP;   ///< sender IP address ( 4 bytes )
    MAC_addr rMAC;  ///< sender MAC address ( 6 bytes )
    IP_addr  rIP;   ///< sender IP address ( 4 bytes )
}H_A;
/**
 * structure of ARP packet
 * we are trying to finish the architecture of this packet, but it may be useless!
 */
typedef struct arp
{
    H_A header;
    u_char * padding;   ///< 18 bytes ( to satisfy 64 bytes )
}ARP;
#endif // ARP_H_INCLUDED





