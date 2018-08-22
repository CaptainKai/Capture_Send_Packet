/**
* @file     Send.cpp
* @brief    the process of sending a packet
* @author   kaili
* @date     2018年4月14日14:17:47
* @version  A001
*/
#include <functions.h>
#define HAVE_REMOTE
#include <remote-ext.h>
void send()
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 找到并打开输出设备 */
    pcap_if_t *alldevs,*d;
    findDevice( &alldevs, &d );

    if ( (fp= pcap_open(d->name,            // 设备名
                        100,                // 要捕获的部分 (只捕获前100个字节)
                        PCAP_OPENFLAG_PROMISCUOUS,  // 混杂模式
                        1000,               // 读超时时间
                        NULL,               // 远程机器验证
                        errbuf              // 错误缓冲
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        return;
    }

    /*选择发包种类发包*/
    char packtype[4];
    printf("Please input the packet type:\t");
    scanf("%s",packtype);
    u_char * packet = NULL;
    if( strcmp( packtype, "arp" ) ==0 || strcmp( packtype, "ARP" ) ==0 || strcmp( packtype, "Arp" ) ==0 )
        sendARP( fp );
    else if( strcmp( packtype, "tcp" ) ==0 || strcmp( packtype, "TCP" ) ==0 )
        sendTCP( fp );
    system("pause");
    return;

}
