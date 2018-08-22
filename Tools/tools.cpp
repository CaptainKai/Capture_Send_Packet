#include <tools.h>
void printD(pcap_if_t *d )
{
    printf("(%s)\n",d->description);

//    if( d->addresses->addr->sa_data != NULL)
//    {
//        struct sockaddr_in * addr = (struct sockaddr_in *)d->addresses->addr;
//
//        printf("%s\n",inet_ntoa(addr->sin_addr));
//    }
}
void printM( MAC_addr Maddr, FILE * file)
{
    printf("%.2x:",Maddr.addr1);
    fprintf(file, "%.2x:",Maddr.addr1);
    printf("%.2x:",Maddr.addr2);
    fprintf(file, "%.2x:",Maddr.addr2);
    printf("%.2x:",Maddr.addr3);
    fprintf(file, "%.2x:",Maddr.addr3);
    printf("%.2x:",Maddr.addr4);
    fprintf(file, "%.2x:",Maddr.addr4);
    printf("%.2x:",Maddr.addr5);
    fprintf(file, "%.2x:",Maddr.addr5);
    printf("%.2x\n",Maddr.addr6);
    fprintf(file, "%.2x\n",Maddr.addr6);
}
void printE(H_E *e, FILE * file)
{
    printf("----------------Ethernet-----------------\n");
    printf("Destination: ");
    fprintf(file, "----------------Ethernet-----------------\n");
    fprintf(file, "Destination: ");
    if(e->dest_MAC.addr1 & e->dest_MAC.addr2 & e->dest_MAC.addr3 & e->dest_MAC.addr4 & e->dest_MAC.addr5 & e->dest_MAC.addr6 == 0xff )
    {
        printf("(Broadcast)");
        fprintf(file, "(Broadcast)");
    }
    printM( e->dest_MAC, file );
    printf("Source: ");
    fprintf(file, "Source: ");
    printM( e->src_MAC, file );
    printf("type:");
    fprintf(file, "type:");
    switch(e->type)
    {
        case ARP_FRAME : printf(" ARP "); fprintf(file," ARP ");break;
        case IPV4_FRAME : printf(" IPV4 "); fprintf(file, " IPV4 ");break;
        case IPV6_FRAME : printf(" IPV6 "); fprintf(file, " IPV6 ");break;
        default : printf(" UnKnown ");
    }
    printf("(0x%.4x)\n",e->type);//%.2x is for special value 0, which will be correctly 00.
    fprintf(file, "(0x%.4x)\n",e->type);
}
void printI( IP_addr  iaddr, FILE * file )
{
    printf("%d.", iaddr.addr1);
    printf("%d.", iaddr.addr2);
    printf("%d.", iaddr.addr3);
    printf("%d\n", iaddr.addr4);

    fprintf(file, "%d.", iaddr.addr1);
    fprintf(file, "%d.", iaddr.addr2);
    fprintf(file, "%d.", iaddr.addr3);
    fprintf(file, "%d\n", iaddr.addr4);
}
void printA( const u_char * pkt_data )
{
    FILE  * file = fopen("log.txt","a+");
    printf("------------------ARP-------------------\n");
    fprintf(file, "------------------ARP-------------------\n");
    ARP * arpf = ( arp * )( pkt_data + 14 );

    arpf->header.opcode = htons( arpf->header.opcode );
    arpf->header.htype = htons( arpf->header.htype );
    arpf->header.ptype = htons( arpf->header.ptype );

    printf("Hardware type:");
    fprintf(file,"Hardware type:");
    if( arpf->header.htype == 0x0001 )
    {
        printf(" Ethernet ");
        fprintf(file," Ethernet ");
    }

    printf("(%d)\n",arpf->header.htype);
    fprintf(file, "(%d)\n",arpf->header.htype);
    printf("Protocol type:");
    fprintf(file, "Protocol type:");
    switch( arpf->header.ptype )
    {
        case IPV4_FRAME : printf(" IPV4 "); fprintf(file, " IPV4 ");break;
        case IPV6_FRAME : printf(" IPV6 "); fprintf(file, " IPV6 ");break;
        default : printf(" UnKnown "); fprintf(file, " UnKnown ");
    }

    printf("(0x%.4x)\n",arpf->header.ptype);
    fprintf(file,"(0x%.4x)\n",arpf->header.ptype);
    printf("(0x%.4x)\n",arpf->header.ptype);
    fprintf(file, "(0x%.4x)\n",arpf->header.ptype);
    printf("Hardware size: %x\n",arpf->header.hsize);
    fprintf(file, "Hardware size: %x\n",arpf->header.hsize);
    printf("Protocol size: %x\n",arpf->header.pzise);
    fprintf(file, "Protocol size: %x\n",arpf->header.pzise);

    printf("Opcode:");
    fprintf(file, "Opcode:");
    switch( arpf->header.opcode )
    {
        case 0x0001 : printf(" request ");fprintf(file, " request ");break;
        case 0x0002 : printf(" reply ");fprintf(file, " reply ");break;
        default : printf(" UnKnown ");fprintf(file, " UnKnown ");
    }
    printf("(%d)\n",arpf->header.opcode);
    fprintf(file, "(%d)\n",arpf->header.opcode);
    printf("Sender MAC address: ");
    fprintf(file, "Sender MAC address: ");
    printM( arpf->header.sMAC, file);
    printf("Sender IP address: ");
    fprintf(file,"Sender IP address: ");
    printI( arpf->header.sIP, file);
    printf("Target MAC address: ");
    fprintf(file, "Target MAC address: ");
    printM( arpf->header.rMAC, file);
    printf("Target IP address: ");
    fprintf(file,"Target IP address: ");
    printI( arpf->header.rIP, file);
    fclose(file);
}
void printT( const u_char * pkt_data, FILE * file )
{
    //printf("This is TCP packet!\n");
    printf("------------------TCP-------------------\n");
    fprintf(file, "------------------TCP-------------------\n");
    H_T * tcp = ( H_T * ) ( pkt_data + 34 );
    tcp->sport = ntohs( tcp->sport );
    tcp->dport = ntohs( tcp->dport );
    tcp->snum = ntohl( tcp->snum );
    tcp->acknum = ntohl( tcp->acknum );
    tcp->hl_fl = ntohs( tcp->hl_fl );
    tcp->window = ntohs( tcp->window );
    tcp->checksum = ntohs( tcp->checksum );
    printf("Source Port: %d\n",tcp->sport );
    printf("Destination Port: %d\n",tcp->dport );
    //printf("[TCP Segment Len: %d\n",tcp->hlength );
    printf("Sequence number: %ld\n",tcp->snum );
    printf("Acknowledgment number: %ld\n",tcp->acknum );
//    printf("%.4x\n",tcp->hl_fl );
    printf("Header Length: %d bytes (%d)\n",( tcp->hl_fl >> 12 )* 4, tcp->hl_fl >> 12 );
    printf("Flags: 0x%.3x(",tcp->hl_fl & 0x0fff );

    fprintf(file, "Source Port: %d\n",tcp->sport );
    fprintf(file, "Destination Port: %d\n",tcp->dport );
    fprintf(file, "Sequence number: %ld\n",tcp->snum );
    fprintf(file, "Acknowledgment number: %ld\n",tcp->acknum );
    fprintf(file, "Header Length: %d bytes (%d)\n",( tcp->hl_fl >> 12 )* 4, tcp->hl_fl >> 12 );
    fprintf(file, "Flags: 0x%.3x(",tcp->hl_fl & 0x0fff );

    if( ( tcp->hl_fl&0x0100 ) > 0 )
    {
        printf(" Nonce ");
        fprintf(file, " Nonce ");
    }
    if( ( tcp->hl_fl&0x0080 ) > 0 )
    {
        printf(" CWR ");
        fprintf(file, " CWR ");

    }
    if( ( tcp->hl_fl&0x0040 ) > 0 )
    {
        printf(" ECN-Echo }");
        fprintf(file, " ECN-Echo }");
    }
    if( ( tcp->hl_fl&0x0020 ) > 0 )
    {
    printf(" URG ");
    fprintf(file, " URG ");

    }
    if( ( tcp->hl_fl&0x0010 ) > 0 )
    {
        printf(" ACK ");
        fprintf(file, " ACK ");
    }
    if( ( tcp->hl_fl&0x0008 ) > 0 )
    {
        printf(" PUSH ");
        fprintf(file, " PUSH ");

    }
    if( ( tcp->hl_fl&0x0004 ) > 0 )
    {
        printf(" RES ");
        fprintf(file, " RES ");
    }
    if( ( tcp->hl_fl&0x0002 ) > 0 )
    {
        printf(" SYN ");
        fprintf(file, " SYN ");
    }
    if( ( tcp->hl_fl&0x001 ) > 0 )
    {
        printf(" FIN ");
        fprintf(file, " FIN ");
    }
    printf(")\n");
    printf("Window size value: %d\n",tcp->window );
    printf("Checksum: 0x%.4x\n",tcp->checksum );
    printf("Urgent pointer: %d\n",tcp->urgentpoint );

    fprintf(file, ")\n");
    fprintf(file, "Window size value: %d\n",tcp->window );
    fprintf(file, "Checksum: 0x%.4x\n",tcp->checksum );
    fprintf(file, "Urgent pointer: %d\n",tcp->urgentpoint );
}
void printIP4( const u_char * pkt_data )
{
    FILE  * file = fopen("log.txt","a+");
    printf("------------------IPV4-------------------\n");
    fprintf(file, "------------------IPV4-------------------\n");
    H_I * ipv4f = (H_I *)(pkt_data+14);
    ipv4f->crc = ntohs( ipv4f->crc );
    ipv4f->length = ntohs(ipv4f->length);
    ipv4f->id = ntohs(ipv4f->id);
    //printf("Internet Protocol Version %d\n",ipv4f->ver_hl/16);
    printf("Version: %d\n",ipv4f->ver_hl/16);
    printf("Header Length: %d bytes (%d)\n",(ipv4f->ver_hl%16)*4,ipv4f->ver_hl%16);
    printf("Differentiated Services Field: 0x%.2x\n",ipv4f->stype);
    printf("Total Length: %d\n",ipv4f->length );
    printf("Identification: 0x%.4x (%d)\n",ipv4f->id, ipv4f->id );
    printf("Flags: 0x%.2x\n",( ipv4f->flag_fo >> 13 ) & 0x07 );
    printf("Fragment offset: %d\n",ipv4f->flag_fo & 0x1fff );
    printf("Time to live: %d\n",ipv4f->ltime);
    printf("Protocol:");

    fprintf(file, "Version: %d\n",ipv4f->ver_hl/16);
    fprintf(file, "Header Length: %d bytes (%d)\n",(ipv4f->ver_hl%16)*4,ipv4f->ver_hl%16);
    fprintf(file, "Differentiated Services Field: 0x%.2x\n",ipv4f->stype);
    fprintf(file, "Total Length: %d\n",ipv4f->length );
    fprintf(file, "Identification: 0x%.4x (%d)\n",ipv4f->id, ipv4f->id );
    fprintf(file, "Flags: 0x%.2x\n",( ipv4f->flag_fo >> 13 ) & 0x07 );
    fprintf(file, "Fragment offset: %d\n",ipv4f->flag_fo & 0x1fff );
    fprintf(file, "Time to live: %d\n",ipv4f->ltime);
    fprintf(file, "Protocol:");

    switch( ipv4f->protocol )
    {
        case UDP_HFRAME : printf(" UDP ");break;
        case TCP_HFRAME : printf( " TCP " );break;
        case ICMP_HFRAME : printf(" ICMP ");break;
        case EGP_HFRAME : printf(" EGP ");break;
        case IPV6_HFRAME : printf(" IPV6 ");break;
        case OSPF_HFRAME : printf(" OSPF ");break;
        case IGMP_HFRAME : printf(" IGMP ");break;
        default : printf(" Unknown ");
    }

    switch( ipv4f->protocol )
    {
        case UDP_HFRAME : fprintf(file, " UDP ");break;
        case TCP_HFRAME : fprintf(file,  " TCP " );break;
        case ICMP_HFRAME : fprintf(file, " ICMP ");break;
        case EGP_HFRAME : fprintf(file, " EGP ");break;
        case IPV6_HFRAME : fprintf(file, " IPV6 ");break;
        case OSPF_HFRAME : fprintf(file, " OSPF ");break;
        case IGMP_HFRAME : fprintf(file, " IGMP ");break;
        default : fprintf(file, " Unknown ");
    }

    printf("(%d)\n",ipv4f->protocol);
    printf("Header checksum: 0x%.4x\n",ipv4f->crc);
    printf("Source: ");

    fprintf(file, "(%d)\n",ipv4f->protocol);
    fprintf(file, "Header checksum: 0x%.4x\n",ipv4f->crc);
    fprintf(file, "Source: ");

    printI( ipv4f->sIP,file );
    printf("Destination: ");
    fprintf(file,"Destination: ");
    printI( ipv4f->dIP,file );

    switch( ipv4f->protocol )
    {
        case UDP_HFRAME : printf(" UDP context\n");fprintf(file, " UDP context\n");break;
        case TCP_HFRAME : printT( pkt_data, file );break;
        case ICMP_HFRAME : printf(" ICMP context\n");fprintf(file, " ICMP context\n");break;
        case EGP_HFRAME : printf(" EGP context\n");fprintf(file, " EGP context\n");break;
        case IPV6_HFRAME : printf(" IPV6 context\n");fprintf(file, " IPV6 context\n");break;
        case OSPF_HFRAME : printf(" OSPF context\n");fprintf(file, " OSPF context\n");break;
        case IGMP_HFRAME : printf(" IGMP context\n");fprintf(file, " IGMP context\n");break;
        default : printf(" Unknown\n");fprintf(file, " Unknown\n");
    }
    fclose(file);
}
void printIP6( const u_char * pkt_data )
{
    FILE  * file = fopen("log.txt","a+");
    printf("This is a IPV6 packet!\n");
    fprintf(file, "This is a IPV6 packet!\n");
    fclose(file);
}

char *getAddress(sockaddr *addr) {
    static char output[32];
    DWORD ip = ((PSOCKADDR_IN)(addr))->sin_addr.s_addr;
    sprintf(output, "%d.%d.%d.%d", LOBYTE(LOWORD(ip)), HIBYTE(LOWORD(ip)), LOBYTE(HIWORD(ip)), HIBYTE(HIWORD(ip)));
    return output;
}

bool findDevice( pcap_if_t **alldevs, pcap_if_t **d )
{
    /*-------------find a Device---------*/
    char errbuf[ PCAP_ERRBUF_SIZE ];
    if( pcap_findalldevs( alldevs, errbuf ) == -1 )
    {
        fprintf( stderr, "Error in pcap_findalldevs:%s\n", errbuf );
        return false;
    }
    /*--------------print Device---------------*/
    FILE * file = fopen("log.txt","w+");
    printf("---------------Device List----------------\n");
    fprintf(file, "---------------Device List----------------\n");
    int cnt = 0;
    for( *d = *alldevs; *d != NULL; *d = (*d)->next )
    {
        puts("\n============================\n");
        printf("%d.%s",++cnt,(*d)->name);
        printf("Description: %s\n", (*d)->description ? (*d)->description : "no description");
        printf("Loop back: %s\n",((*d)->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
        printf("Up: %s\n",((*d)->flags & PCAP_IF_UP) ? "yes" : "no");
        printf("Running: %s\n",((*d)->flags & PCAP_IF_RUNNING) ? "yes" : "no");
        for (pcap_addr_t *ap = (*d)->addresses; ap != NULL; ap = ap->next) {
            u_short type = ap->addr->sa_family;
            if (type == AF_INET) { // ipv4
                puts("AF INET ipv4:");
                if (ap->addr) printf("\tipv4 address: %s\n", getAddress(ap->addr));
                if (ap->netmask) printf("\tnet mask: %s\n", getAddress(ap->netmask));
                if (ap->broadaddr) printf("\tbroad address: %s\n", getAddress(ap->broadaddr));
                if (ap->dstaddr) printf("\tdestination address: %s\n", getAddress(ap->dstaddr));
            }
        }

//        cnt++;
//        printf("%d.%s",cnt,(*d)->name);
//        fprintf(file,"%d.%s\n",cnt,(*d)->name);
//        if( (*d)->description != NULL )
//        {
//            printD(*d);
//        }
//        else
//        {
//            printf("(NO description!)\n");
//        }
    }
    if( cnt == 0 )
    {
        printf("\nNo interfaced found!\n");
        printf("Make sure WinPcap or npcap is installed.\n");

        fprintf(file, "\nNo interfaced found!\n");
        fprintf(file, "Make sure WinPcap or npcap is installed.\n");

        pcap_freealldevs( *alldevs );
        return false;
    }

    /*-------------choose a Device-------------*/
    printf("Choose a Device (1-%d):\t",cnt);
    fprintf(file, "Choose a Device (1-%d):\t",cnt);
    int DNum;
    scanf("%d",&DNum);
    fprintf(file, "%d\n", DNum);
    if(DNum < 1 || DNum > cnt)
    {
        printf("\nOver the range.\n");
        fprintf(file, "\nOver the range.\n");
        pcap_freealldevs(*alldevs);
        return false;
    }
    *d = *alldevs;
    for( int i = 0; i< DNum-1; *d = (*d)->next, i++ );
    fclose(file);
    return true;
}
bool filter( pcap_if_t **alldevs, pcap_t **adhandle, u_int netmask)
{
    char condi[15];
    struct bpf_program fcode;
    FILE * file = fopen("log.txt","a+");
    printf("Please input the bool expression:    ");
    scanf("%s",condi);

    fprintf(file, "Please input the bool expression:    ");
    fprintf(file, "%s",condi);

    if (pcap_compile(*adhandle, &fcode, condi, 1, netmask) < 0)
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        pcap_freealldevs( *alldevs );
        return false;
    }
//set the filter
    if ( pcap_setfilter( *adhandle, &fcode ) < 0 )
    {
        fprintf( stderr, "\nError setting the filter.\n" );
        pcap_freealldevs( *alldevs );
        return false;
    }

    return true;
}

void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;
    FILE  * file = fopen("log.txt","a+");

    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("------------------Time-------------------\n");
    printf("%s, len:%d\n", timestr, header->len);

    fprintf(file, "------------------Time-------------------\n");
    fprintf(file, "%s, len:%d\n", timestr, header->len);

    //printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);//

    //-------------Ethernet-----------------
    //find the head of Ethernet
    H_E * e = ( H_E * )pkt_data;
    //change big-endian to little-endian
    e->type = htons( e->type );
    printE( e, file );
    fclose( file );
    switch( e->type )
    {
        case ARP_FRAME : printA( pkt_data );break;
        case IPV4_FRAME : printIP4( pkt_data );break;
        case IPV6_FRAME : printIP6( pkt_data );break;
        default : printf(" UnKnown ");
    }
    //changing----------------------------------
}
//-------------------------------------send-----------
void sendARP( pcap_t * fp )
{
    //H_E EthNet;
    u_char packet[60];
    printf("--------------Send Ethernet---------------\n");
    printf("Please input the Destination MAC address: eg. ff ff ff ff ff ff\n  ");
    for( int i = 0 ; i < 6 ; i++ )
        scanf("%x",( packet + i ) );
    printf("Please input the Source MAC address: eg. 5c e0 c5 be 98 3a\n  ");
    for( int i = 6 ; i < 12 ; i++ )
        scanf("%x",( packet + i ) );
//    packet[ 6 ] = 0x5c;
//    packet[ 7 ] = 0xe0;
//    packet[ 8 ] = 0xc5;
//    packet[ 9 ] = 0xbe;
//    packet[ 10 ] = 0x98;
//    packet[ 11 ] = 0x3a;

    packet[12] = 0x08 ;
    packet[13] = 0x06 ;
    printf("Ethernet Done!\n");
    //--------------arp-----------
    packet[14] = 0x00;//Hardware type
    packet[15] = 0x01;
    packet[16] = 0x08;//Protocol type
    packet[17] = 0x00;
    packet[18] = 0x06;//Hardware size
    packet[19] = 0x04;//Protocal size
    packet[20] = 0x00;//opcode
    for( int i=0;i<6;i++)
    {
        if( packet[i] != 0xff )
        {
            packet[21] = 0x02;
            break;
        }
    }
    packet[21] = packet[21]==0x02 ? 0x02 : 0x01;
    printf("the opcode is");
    if( packet[21] == 0x02 )
        printf(" reply ");
    else
        printf(" request ");
    printf("(%x)\n", packet[21]);
    /*--------arp内容(随便填充)----------*/
    for(int i=22;i<28;i++)
        packet[i] = packet[i-16];

    printf("please input the Sender IP address: eg. 10 18 141 38\n\t");
    for(int i=28;i<32;i++)
        scanf("%d", packet + i );

    //填充为0 才对
    if( packet[21] == 0x01)
    {
       for(int i=32;i<38;i++)
            packet[i] = 0x00;
    }
    else
    {
        for(int i=32;i<38;i++)
            packet[i] = packet[i-32];
    }


    printf("please input the Target IP address: eg. 10 18 141 90\n\t");
    for(int i=38;i<42;i++)
        scanf("%d", packet + i );
    /*----------填充0-----------*/
    for(int i=42;i<60;i++)
        packet[i]=0;
    printf("ARP Done!\n");

    if (pcap_sendpacket(fp, packet, 60 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return ;
    }
    return ;

}
void sendTCP( pcap_t * fp )
{
    //printf(" Send TCP Packet...... \n");
    u_char packet[54];
    printf("-----------------Send IP------------------\n");
    printf("Please input the Destination MAC address:( 6 bytes )\n  ");
    for( int i = 0 ; i < 6 ; i++ )
        scanf("%x",( packet + i ) );

    printf("Please input the Source MAC address: eg, 5c e0 c5 be 98 3a\n  ");
    for( int i = 6 ; i < 12 ; i++ )
        scanf("%x",( packet + i ) );

//    packet[ 6 ] = 0x5c;
//    packet[ 7 ] = 0xe0;
//    packet[ 8 ] = 0xc5;
//    packet[ 9 ] = 0xbe;
//    packet[ 10 ] = 0x98;
//    packet[ 11 ] = 0x3a;

    packet[12] = 0x08 ;
    packet[13] = 0x00 ;

    printf("Ethernet Done!\n");
    //--------------ip-----------
    //version-length service
    packet[14] = 0x45;
    packet[15] = 0x00;
    //total lenth
    printf("Please set total length ( IP ), (eg: 00 28)\n  ");
    scanf("%x%x",(packet + 16), ( packet + 17 ));
    //identification
    printf("Please set identification, (eg: 14 3e)\n  ");
    scanf("%x%x",(packet + 18), ( packet + 19 ));
    //flags_f0
    printf("Please set Flags and Fragment offset: (eg: 40 00)\n  ");
    //    Don't fragment: input 4
    //    More fragment: input 2
    scanf("%x%x",(packet + 20), (packet + 21) );
    //time to live
    printf("Please set Time to live: (eg: 80)\n  ");
    //    Don't fragment: input 4
    //    More fragment: input 2
    scanf("%x",(packet + 22) );
    //06 (TCP)
    packet[23] = 0x06;
    //checksum 默认为Enable 不计算
    packet[24] = 0x00;
    packet[25] = 0x00;
    //sIP
    printf("Please set Source IP: ( 4 bytes )\n  ");
    for( int i = 26 ; i < 30 ; i++ )
        scanf("%d",( packet + i ) );
    //dIP
    printf("Please set Destinaiton IP: ( 4 bytes )\n  ");
    for( int i = 30 ; i < 34 ; i++ )
        scanf("%d",( packet + i ) );
    printf("-----------------Send TCP------------------\n");
    //sPORT
    printf("Please set Source Port: ( 2 bytes 16进制 )\n  ");
    scanf("%x%x",( packet + 34 ),( packet + 35 ) );
    //dport
    printf("Please set destination Port: ( 2 bytes 16进制 )\n  ");
    scanf("%x%x",( packet + 36 ),( packet + 37 ) );
    //sequence num
    printf("Please set Sequence number: ( 4 bytes 10进制 )\n  ");
    for( int i = 38 ; i < 42 ; i++ )
        scanf("%d",( packet + i ) );
    //ack num
    printf("Please set Acknowledge number: ( 4 bytes 10进制 )\n  ");
    for( int i = 42 ; i < 46 ; i++ )
        scanf("%d",( packet + i ) );
    //header_fl
    printf("Please set Header Length and Flags: (eg: 50 18)\n  ");
    scanf("%x%x",( packet + 46 ),( packet + 47 ) );
    printf("Please set Window size: ( 2 bytes 16进制 )\n  ");
    scanf("%x%x",( packet + 48 ),( packet + 49 ) );
    //checksum
    //checksum
    packet[50] = 0x00;
    packet[51] = 0x00;
    //urgent pointer
    printf("Please set Urgent pointer: ( eg: 00 00)\n  ");
    scanf("%x%x",( packet + 52 ),( packet + 53 ) );
    //option context
    unsigned short int tlength = *( packet + 16 )* 512 + *( packet + 17 );
    if( tlength > 40 )
    {

        u_char * rpacket = ( u_char * )malloc( sizeof( u_char )* ( tlength + 14 ));
        strcpy( ( char * )rpacket, ( char * )packet );
        printf("Please input the option context: ( %d bytes )\n  ",( tlength - 40 ) );
        for(int i = 54; i < ( tlength + 14 ); i++ )
        {
            scanf("%x",( rpacket + i) );
        }

    }
    //send
    if (pcap_sendpacket(fp, packet, ( tlength + 14 ) /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
        return ;
    }
    printf("TCP Done!\n");
    return ;
}
