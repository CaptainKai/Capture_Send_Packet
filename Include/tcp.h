/**
* @file     tcp.h
* @brief    TCP packet data structure
* @details  only TCP head data structure without optional context
* @author   KaiLi
* @date     2018年3月13日10:23:42
* @version  A001
* @par History:
*   version: author, date, desc\n
*/
#ifndef TCP_H_INCLUDED
#define TCP_H_INCLUDED
#include <datatype.h>
typedef struct Header_T
{
    hword sport;    ///< source port ( 2 bytes )
    hword dport;    ///< destination port ( 2 bytes )
    word snum;      ///< sequence number ( 4 bytes )
    word acknum;    ///< acknowledge number ( 4 bytes )
    hword hl_fl;    ///< head length ( IP ): 8 flag :8 (2 bytes )
    hword window;   ///< window size ( 2 bytes )
    hword checksum; ///< checksum ( 2 bytes )
    hword urgentpoint;  ///< urgent pointer ( 2 bytes )
}H_T;


#endif // TCP_H_INCLUDED
