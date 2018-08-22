/**
* @file    ip.h
* @brief   ip structure
* @details 利用自定义的基本数据类型构造了IP的头部数据结构（截止到TCP头部起始位置）；目前只有IPV4版本
* @author  KaiLi
* @date    2018年3月12日20:05:51
* @version A001（ IPV4 ）
* @par History:
*   version: author, date, desc\n
*/
#ifndef IP_H_INCLUDED
#define IP_H_INCLUDED
#include <datatype.h>
/**
 * IP packet
 * only IPV4
 */
typedef struct Header_IP4
{
    byte ver_hl;    ///< version(4), Length(4)
    byte stype;     ///< service type
    hword length;   ///< total length
    hword id;       ///< identification
    hword flag_fo;  ///< flag(3), fragment offset(13)
    byte ltime;     ///< life time
    byte protocol;  ///< protocol
    hword crc;      ///< checksum
    IP_addr sIP;    ///< Source IP address
    IP_addr dIP;    ///< Destination IP address
}H_I;
#endif // IP_H_INCLUDED

