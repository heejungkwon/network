#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

/* Function to print the first 16 bytes of packet data */
void print_packet_data(const u_char* packet, int data_len) {
    printf("Data: ");
    for (int i = 0; i < data_len && i < 16; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n\n");
}

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ethheader* eth = (struct ethheader*)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader* ip = (struct ipheader*)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + (ip->iph_ihl << 2));

            printf("Ethernet Header\n");
            printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("\nIP Header\n");
            printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));

            printf("\nTCP Header\n");
            printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
            printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

            int ip_header_len = ip->iph_ihl * 4; // Convert to bytes
            int tcp_header_len = tcp->tcp_offx2 >> 4; // Convert to bytes
            int data_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

            // Print data (up to 16 bytes)
            print_packet_data(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len, data_len);
        }
    }
}

int main() {
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name ens33
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "err: %s\n", errbuf);
        return 1;
    }

    // Step 2: Compile filter_exp into BPF psuedo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "err %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "err %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Step 3: Capture packets
    pcap_loop(handle, 0, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
}
