#include <functions.h>
#define LoopCap
void capture()
{
    //printf("function capture work properly!\n");//for test
    //----------------find Device:---------------------
    pcap_if_t *alldevs,*d;
    if( findDevice( &alldevs, &d ) == false )
    {
        printf("No Device!\n");
        return;
    }
    char errbuf[ PCAP_ERRBUF_SIZE ];
    pcap_t * adhandle = pcap_open_live(d->name,65536,1,1000,errbuf);//
    if( adhandle == NULL )
    {
        fprintf( stderr, "\nCan not open the handler.%s Not support WinPcap\n" , d->name );
		pcap_freealldevs( alldevs );
        exit( 1 );
    }
    /*---------------检查数据链路层，只考虑以太网--------*/
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
        netmask=0xffffff;

    filter( &alldevs, &adhandle, netmask);
    FILE * file = fopen("log.txt","a+");
    printf("listening on %s...\n", d->description);
    fprintf(file, "listening on %s...\n", d->description);
    fclose(file);
    pcap_freealldevs( alldevs );
    //-----------NEXT_CAP-----------------------------------
    #ifdef Next_Direct
    int res;
    struct tm *ltime;
    //time_t local_tv_sec;
    char timestr[16];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        if (res == 0)
        {
            continue;  		 /* Timeout elapsed */
        }
  			/* convert the timestamp to readable format */
        ltime = localtime(&header->ts.tv_sec);
        strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
        printf("%s, %.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    }
    if (res == -1)
    {
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }
    #endif // Next_Direct

    //--------------------LOOPCAP-------------------------------------
    #ifdef LoopCap
    pcap_loop( adhandle, 0, packet_handler, NULL );//
    pcap_close( adhandle );
    #endif // LoopCap
}
