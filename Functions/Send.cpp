/**
* @file     Send.cpp
* @brief    the process of sending a packet
* @author   kaili
* @date     2018��4��14��14:17:47
* @version  A001
*/
#include <functions.h>
#define HAVE_REMOTE
#include <remote-ext.h>
void send()
{
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* �ҵ���������豸 */
    pcap_if_t *alldevs,*d;
    findDevice( &alldevs, &d );

    if ( (fp= pcap_open(d->name,            // �豸��
                        100,                // Ҫ����Ĳ��� (ֻ����ǰ100���ֽ�)
                        PCAP_OPENFLAG_PROMISCUOUS,  // ����ģʽ
                        1000,               // ����ʱʱ��
                        NULL,               // Զ�̻�����֤
                        errbuf              // ���󻺳�
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        return;
    }

    /*ѡ�񷢰����෢��*/
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
