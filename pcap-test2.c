#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct ethernet_hdr {
    uint8_t ether_dhost[6]; //Destination 90:9f:33:d9:a0:e3 5
    uint8_t ether_shost[6]; //Source b4:2e:99:ea:97:de  5
    uint16_t ether_type; //type 
};

struct ipv4_hdr {
    uint8_t ip_hl:4, ip_v:4; //4byte 4byte
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

struct tcp_hdr {
    uint16_t th_sport; //4byte
    uint16_t th_dport; //4byte
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_x2:4, th_off:4;
    uint8_t th_flags;
    uint16_t th_win;
    uint16_t th_sum;
    uint16_t th_urp;
};

void print_mac(uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(struct in_addr ip) {
    printf("%s", inet_ntoa(ip));
}

void print_payload(const u_char* payload, int len) {
    int print_len = (len > 20) ? 20 : len;
    for (int i = 0; i < print_len; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
//-------------------------------------------------------

        struct ethernet_hdr* eth_hdr = (struct ethernet_hdr*)packet;
        if (ntohs(eth_hdr->ether_type) != 0x0800)
            continue; //ipv4 header -------

        struct ipv4_hdr* ip_hdr = (struct ipv4_hdr*)(packet + sizeof(struct ethernet_hdr));
        if (ip_hdr->ip_p != 6) // TCP header--------
            continue;

        struct tcp_hdr* tcp_hdr = (struct tcp_hdr*)(packet + sizeof(struct ethernet_hdr) + (ip_hdr->ip_hl * 4));

        printf("1.Ethernet Header\n");
        printf("  Src MAC: ");
        print_mac(eth_hdr->ether_shost);
        printf("\n  Dst MAC: ");
        print_mac(eth_hdr->ether_dhost);
        printf("\n");

        printf("2.IP Header\n");
        printf(" Src IP: ");
        print_ip(ip_hdr->ip_src);
        printf("\nDst IP: ");
        print_ip(ip_hdr->ip_dst);
        printf("\n");

        printf("3.TCP Header\n");
        printf(" Src Port: %d\n", ntohs(tcp_hdr->th_sport));
        printf(" Dst Port: %d\n", ntohs(tcp_hdr->th_dport));

        int header_len = sizeof(struct ethernet_hdr) + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4);
        const u_char* payload = packet + header_len;
        int payload_len = header->caplen - header_len;
	//header = eth + ipv4 -> tcp = all - header

        printf("4. Payload (Hexadecimal, up to 20 bytes)\n");
        print_payload(payload, payload_len);

        printf("\n");
    }

    pcap_close(pcap);
    return 0;
}
