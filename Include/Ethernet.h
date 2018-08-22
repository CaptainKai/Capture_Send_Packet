/**
* @file     Ethernet.h
* @brief    Ethernet packet head data structure
* @details  14 bytes head, consisted of MAC address,without checksum
* @author   KaiLi
* @date     2018年3月13日10:20:40
* @version  A001
* @par History:
*   version: author, date, desc\n
*/
#ifndef ETHERNET_H_INCLUDED
#define ETHERNET_H_INCLUDED
#include <datatype.h>
/**
 * the head data structure of Ethernet packet
 * 14 bytes
 */
typedef struct Header_E
{
    MAC_addr dest_MAC;  ///< Destination MAC address ( 6 bytes )
    MAC_addr src_MAC;   ///< Source MAC address ( 6 bytes )
    hword  type;        ///< suggest the packet's type under the Ethernet ( 2 bytes )
}H_E;
/**
 * structure of Ethernet packet
 * we are trying to finish the architecture of this packet, but it may be useless!
 * with 4 bytes FCS but without the body context. The MAC CRC ( FCS part） doesn't need to be included, because it is transparently calculated and added by the network interface driver.
 */
typedef struct Ethernet
{
    Header_E header;
    word  FCS;          ///< checksum but not appear in real packet
}Ethernet;


#endif // ETHERNET_H_INCLUDED
