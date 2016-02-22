/* Modified From: http://inst.eecs.berkeley.edu/~ee122/fa07/projects/p2files/packet_parser.c*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pcap.h>
#include "util.h"

#define BUFFER_SIZE 80

typedef struct _connection {
	char ip_src[BUFFER_SIZE]; /* source IP */
	char ip_dst[BUFFER_SIZE]; /* destination IP */
	uint16_t port_src; /* source port number */
	uint16_t port_dst; /* destination port number */
	int syn_count; /* flag count */
	int fin_count;
	int rst_count;
	struct timeval starting_time;
	struct timeval ending_time;
	struct timeval duration;
	int num_packet_src; /* number of packets sent out by source */
	int num_packet_dst; /* number of packets sent out by destination */
	int num_total_packets;
	int cur_data_len_src; /* number of data bytes by source */
	int cur_data_len_dst; /* number of data bytes by destination */
	int cur_total_data_len;
} connection;

int totalConnection = 0;

pcap_t* build_filter(char* fileName, char *errbuf, struct bpf_program *fp, char *filter_exp);
int uniqueConnection(connection *conn, connection **connArray);

/* process_TCP_packet()
 *
 * This routine parses a packet, expecting Ethernet, IP, and UDP headers.
 * It extracts the UDP source and destination port numbers along with the UDP
 * packet length by casting structs over a pointer that we move through
 * the packet.  We can do this sort of casting safely because libpcap
 * guarantees that the pointer will be aligned.
 *
 * The "ts" argument is the timestamp associated with the packet.
 *
 * Note that "capture_len" is the length of the packet *as captured by the
 * tracing program*, and thus might be less than the full length of the
 * packet.  However, the packet pointer only holds that much data, so
 * we have to be careful not to read beyond it.
 */
void process_TCP(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len, struct ip **ip, struct tcphdr **tcp, int *payload_size)
{
	unsigned int IP_header_length;

	/* For simplicity, we assume Ethernet encapsulation. */

	if (capture_len < sizeof(struct ether_header))
	{
		/* We didn't even capture a full Ethernet header, so we
		 * can't analyze this any further.
		 */
		too_short(ts, "Ethernet header");
		return;
	}

	/* Skip over the Ethernet header. */
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

	if (capture_len < sizeof(struct ip))
	{
		/* Didn't capture a full IP header */
		too_short(ts, "IP header");
		return;
	}

	*ip = (struct ip*) packet;
	IP_header_length = (**ip).ip_hl * 4;	/* ip_hl is in 4-byte words */

	if (capture_len < IP_header_length)
	{
		/* didn't capture the full IP header including options */
		too_short(ts, "IP header with options");
		return;
	}

	if ((**ip).ip_p != IPPROTO_TCP)
	{
		problem_pkt(ts, "non-TCP packet");
		return;
	}

	/* Skip over the IP header to get to the TCP header. */
	packet += IP_header_length;
	capture_len -= IP_header_length;

	if (capture_len < sizeof(struct tcphdr))
	{
		too_short(ts, "TCP header");
		return;
	}

	*tcp = (struct tcphdr*) packet;

    capture_len -= (**tcp).th_off * 4;
    *payload_size = capture_len;

	// char *src_addr = malloc(BUFFER_SIZE);
	// strncpy(src_addr, inet_ntoa((**ip).ip_src), BUFFER_SIZE);
    //
	// char *dst_addr = malloc(BUFFER_SIZE);
	// strncpy(dst_addr, inet_ntoa((**ip).ip_dst), BUFFER_SIZE);
    //
	// printf("%s TCP src_addr=%s src_port=%d  dst_addr=%s dst_port=%d\n",
	// 	timestamp_string(ts),
	// 	src_addr,
	// 	ntohs((**tcp).th_sport),
	// 	dst_addr,
	// 	ntohs((**tcp).th_dport)
	// );
}

int uniqueConnection(connection *conn, connection **connArray)
{
    for (int i = 0; i < totalConnection; i++)
    {
        if ((strcmp(conn->ip_src, connArray[i]->ip_src) == 0) &&
            (strcmp(conn->ip_dst, connArray[i]->ip_dst) == 0) &&
            conn->port_src == connArray[i]->port_src &&
            conn->port_dst == connArray[i]->port_dst)
        {
            return -1;
        }

    }
    return 0;
}


int main(int argc, char *argv[])
{
	pcap_t *pcap;
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[BUFFER_SIZE] = "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0";	/* The filter expression */
    // char filter_exp[] = "tcp";
    const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;

	/* Skip over the program name. */
	++argv; --argc;

	/* We expect exactly one argument, the name of the file to dump. */
	if ( argc != 1 )
	{
		fprintf(stderr, "program requires one argument, the trace file\n");
		exit(1);
	}

    pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

    int connNum = 0;
    while ((pcap_next(pcap, &header)) != NULL)
    {
        connNum++;
    }
    connection **connArray = (connection **) malloc(connNum * sizeof(connection *));

    pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

    //Create Connection
    struct ip *ip;
    struct tcphdr *tcp;
    int payload_size;
	while ((packet = pcap_next(pcap, &header)) != NULL)
    {
		process_TCP(packet, header.ts, header.caplen, &ip, &tcp, &payload_size);

        connection *conn = malloc(sizeof(connection));
        memset(conn, 0, sizeof(connection));
        strncpy(conn->ip_src, inet_ntoa(ip->ip_src), BUFFER_SIZE);
        strncpy(conn->ip_dst, inet_ntoa(ip->ip_dst), BUFFER_SIZE);
        conn->port_src = ntohs(tcp->th_sport);
        conn->port_dst = ntohs(tcp->th_dport);

        if (uniqueConnection(conn, connArray) == 0)
        {
            connArray[totalConnection] = conn;
            totalConnection++;
        }
    }

    printf("A) Total number of connections: %d\n", totalConnection);

    for (int i = 0; i < totalConnection; i++) {
        connection *temp = connArray[i];
        char filter_template[] = "ip host %s and ip host %s and port %d and port %d";
        sprintf(filter_exp, filter_template, temp->ip_src, temp->ip_dst, temp->port_src, temp->port_dst);

        pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

        while ((packet = pcap_next(pcap, &header)) != NULL)
        {
            process_TCP(packet, header.ts, header.caplen, &ip, &tcp, &payload_size);

            if (timerisset(&temp->starting_time) == 0) {
                temp->starting_time = header.ts;
            }

            switch(tcp->th_flags) {
                case TH_SYN:
                    temp->syn_count++;
                case TH_FIN:
                    temp->fin_count++;
                case TH_RST:
                    temp->rst_count++;
            }

            if ((temp->syn_count >= 1) &&
                (temp->fin_count >= 1))
            {
                temp->ending_time = header.ts;
            }

            if (strcmp(temp->ip_src, inet_ntoa(ip->ip_src)) == 0)
            {
                temp->num_packet_src++;
                temp->cur_data_len_src += payload_size;
            }
            else if (strcmp(temp->ip_dst, inet_ntoa(ip->ip_src)) == 0)
            {
                temp->num_packet_dst++;
                temp->cur_data_len_dst += payload_size;
            }
        }

        printf("Connection: %d\n", i);
        printf("Source Address: %s\n", temp->ip_src);
        printf("Destination Address: %s\n", temp->ip_dst);
        printf("Source Port: %d\n", temp->port_src);
        printf("Destination Port: %d\n", temp->port_dst);

        if ((temp->syn_count >= 1) &&
            (temp->fin_count >= 1))
        {
            timersub(&temp->ending_time, &temp->starting_time, &temp->duration);
            temp->num_total_packets = temp->num_packet_src + temp->num_packet_dst;
            temp->cur_total_data_len = temp->cur_data_len_src + temp->cur_data_len_dst;

            printf("Status: S%dF%d\n", temp->syn_count, temp->fin_count);
            printf("Start Time: %s\n", timestamp_string(temp->starting_time));
            printf("End Time: %s\n", timestamp_string(temp->ending_time));
            printf("Duration: %s\n", timestamp_string(temp->duration));
            printf("Number of packets sent from Source to Destination: %d\n", temp->num_packet_src);
            printf("Number of packets sent from Destination to Source: %d\n", temp->num_packet_dst);
            printf("Total Number of packets: %d\n", temp->num_total_packets);
            printf("Number of data bytes sent from Source to Destination: %d\n", temp->cur_data_len_src);
            printf("Number of data bytes sent from Destination to Source: %d\n", temp->cur_data_len_dst);
            printf("Total Number of data bytes: %d\n", temp->cur_total_data_len);
            printf("END\n");
            printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            printf("\n");

        }
    }

	// terminate
	return 0;
}

pcap_t* build_filter(char* fileName, char *errbuf, struct bpf_program *fp, char *filter_exp)
{
    pcap_t *pcap;

    pcap = pcap_open_offline(fileName, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "error reading pcap file: %s\n", errbuf);
        exit(1);
    }

    if(pcap_compile(pcap, fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        exit(2);
    }

    if (pcap_setfilter(pcap, fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
        exit(2);
    }
    return pcap;
}
