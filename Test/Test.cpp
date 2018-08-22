#include <hmain.h>
#ifdef TEST
int main()
{
    printf("This is Test result!\n");
    pcap_if_t *alldevs,*d;
    findDevice( &alldevs, &d );
    char errbuf[ PCAP_ERRBUF_SIZE ];
    pcap_t * adhandle = pcap_open_live(d->name,65536,1,1000,errbuf);//
    if( adhandle == NULL )
    {
        fprintf( stderr, "\nCan not open the handler.%s Not support WinPcap\n" , d->name );
		pcap_freealldevs( alldevs );
        exit( 1 );
    }
    /* 检查数据链路层，只考虑以太网 */
    if(pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        pcap_freealldevs(alldevs);
        exit( 1 );
    }

    u_int netmask;
    if ( d->addresses != NULL )
        netmask=((struct sockaddr_in *)( d->addresses->netmask ) )->sin_addr.S_un.S_addr;
    else
        //why?
        netmask=0xffffff;

    filter( &alldevs, &adhandle, netmask);

    printf("listening on %s...\n", d->description);
    pcap_freealldevs( alldevs );

}
#endif // TEST()

