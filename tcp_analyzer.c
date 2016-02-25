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
#include <limits.h>
#include "util.h"
#include "analyzer.h"

int totalConnection = 0;

pcap_t* build_filter(char* fileName, char *errbuf, struct bpf_program *fp, char *filter_exp);
int uniqueConnection(connection *conn, connection **connArray);


/* Break down a TCP packet and extract relevant Information */
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
	IP_header_length = (*ip)->ip_hl * 4;	/* ip_hl is in 4-byte words */

	if (capture_len < IP_header_length)
	{
		/* didn't capture the full IP header including options */
		too_short(ts, "IP header with options");
		return;
	}

    /* Check if it is a TCP packet */
	if ((*ip)->ip_p != IPPROTO_TCP)
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

    /* Skipping over TCP header gives the remaining payload size */
    capture_len -= (*tcp)->th_off * 4;
    *payload_size = capture_len;

}

/* Check if another connection with the same 4-tuple already exists */
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

void getConnectionInfo(connection *conn, pcap_t *pcap, int *totalReset, struct pcap_pkthdr *header)
{
    const unsigned char *packet;
    struct ip *ip;
    struct tcphdr *tcp;

    conn->min_win_size = UINT16_MAX;
    while ((packet = pcap_next(pcap, header)) != NULL)
    {
        int payload_size = 0;
        process_TCP(packet, header->ts, header->caplen, &ip, &tcp, &payload_size);

        if (timerisset(&conn->starting_time) == 0) conn->starting_time = header->ts;

        if (tcp->th_flags & TH_SYN) conn->syn_count++;
        if (tcp->th_flags & TH_FIN) conn->fin_count++;

        /* if the same TCP connection was reset multiple times, it should be counted as ONE reset TCP connection.*/
        if((tcp->th_flags & TH_RST) && conn->rst_count == 0) {
            conn->rst_count++;
            *totalReset = *totalReset + 1;

            //An incomplete connection has been reset. So, reset everything
            if (conn->fin_count == 0)
            {
                conn->syn_count = 0;
                conn->fin_count = 0;
                conn->num_packet_src = 0;
                conn->cur_data_len_src = 0;
                conn->num_packet_dst = 0;
                conn->cur_data_len_dst = 0;
                conn->min_win_size = UINT16_MAX;
                conn->max_win_size = 0;
                conn->sum_win_size = 0;
            }
        }

        /*From Source */
        if (strcmp(conn->ip_src, inet_ntoa(ip->ip_src)) == 0)
        {
            conn->num_packet_src++;
            conn->cur_data_len_src += payload_size;
        }
        /*From Destination */
        else if (strcmp(conn->ip_dst, inet_ntoa(ip->ip_src)) == 0)
        {
            conn->num_packet_dst++;
            conn->cur_data_len_dst += payload_size;
        }

        /* Get Window Sizes */
        if (htons(tcp->th_win) > conn->max_win_size) conn->max_win_size = htons(tcp->th_win);
        if (htons(tcp->th_win) < conn->min_win_size) conn->min_win_size = htons(tcp->th_win);
        conn->sum_win_size += htons(tcp->th_win);

        //Connection Establishment SYN/ACK packets
        if (conn->expected_ack_len < 2)
        {
            conn->expected_ack[conn->expected_ack_len].number = ntohl(tcp->th_seq) + 1;
        }
        else if (tcp->th_flags & TH_ACK)
        {
            conn->expected_ack[conn->expected_ack_len].number = ntohl(tcp->th_seq) + payload_size;
        }
        conn->expected_ack[conn->expected_ack_len].time = header->ts;
        conn->expected_ack_len++;

        conn->actual_ack[conn->actual_ack_len].number = ntohl(tcp->th_ack);
        conn->actual_ack[conn->actual_ack_len].time = header->ts;
        conn->actual_ack_len++;
    }
}

void computeRTT(connection *conn, struct _generalStatsStruct *stats)
{
    double rtt;

    for (int i = 0; i < conn->expected_ack_len; i++) {

        for (int j = 0; j < conn->actual_ack_len; j++) {
            rtt = getDuration(&conn->expected_ack[i].time, &conn->actual_ack[j].time);

            if ((conn->expected_ack[i].number == conn->actual_ack[j].number) &&
                (rtt>0))
            {
                if (rtt < stats->minRTT) stats->minRTT = rtt;
                if (rtt > stats->maxRTT) stats->maxRTT = rtt;
                stats->totalRTT += rtt;
            }
        }
    }
}

void printCompleteConnection(connection *conn, struct _generalStatsStruct *stats, struct pcap_pkthdr *header)
{
    conn->ending_time = header->ts;
    conn->duration = getDuration(&conn->starting_time, &conn->ending_time);
    conn->num_total_packets = conn->num_packet_src + conn->num_packet_dst;
    conn->cur_total_data_len = conn->cur_data_len_src + conn->cur_data_len_dst;
    /* Update Min, Max, Total Duration*/
    if (conn->duration < stats->minDuration)   stats->minDuration = conn->duration;
    if (conn->duration > stats->maxDuration)   stats->maxDuration = conn->duration;
    stats->totalDuration += conn->duration;
    /* Update Min, Max, Total Packet*/
    if (conn->num_total_packets < stats->minPacket)    stats->minPacket = conn->num_total_packets;
    if (conn->num_total_packets > stats->maxPacket)    stats->maxPacket = conn->num_total_packets;
    stats->totalPacket += conn->num_total_packets;
    /* Update Min, Max, Total Window Size*/
    if (conn->min_win_size < stats->minWindow) stats->minWindow = conn->min_win_size;
    if (conn->max_win_size > stats->maxWindow) stats->maxWindow = conn->max_win_size;
    stats->totalWindow += conn->sum_win_size;

    printf("Start Time: %s\n", timestamp_string(conn->starting_time));
    printf("End Time: %s\n", timestamp_string(conn->ending_time));
    printf("Duration: %f\n", conn->duration);
    printf("Number of packets sent from Source to Destination: %d\n", conn->num_packet_src);
    printf("Number of packets sent from Destination to Source: %d\n", conn->num_packet_dst);
    printf("Total Number of packets: %d\n", conn->num_total_packets);
    printf("Number of data bytes sent from Source to Destination: %d\n", conn->cur_data_len_src);
    printf("Number of data bytes sent from Destination to Source: %d\n", conn->cur_data_len_dst);
    printf("Total Number of data bytes: %d\n", conn->cur_total_data_len);
}

int main(int argc, char *argv[])
{
	pcap_t *pcap;
	struct bpf_program fp;		/* The compiled filter expression */
    const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
    char filter_exp[BUFFER_SIZE] = "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0";	/* The filter expression */

	/* Skip over the program name. */
	++argv; --argc;

	/* We expect exactly one argument, the name of the file to dump. */
	if ( argc != 1 )
	{
		fprintf(stderr, "program requires one argument, the trace file\n");
		exit(1);
	}

    /* Get SYN only flags */
    pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

    /* Count number of connections, ignore duplicates for now */
    int connNum = 0;
    while ((pcap_next(pcap, &header)) != NULL)
    {
        connNum++;
    }
    /* Create an array to hold the connections */
    connection **connArray = (connection **) malloc(connNum * sizeof(connection *));

    pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

    /* Create each connection */
    struct ip *ip;
    struct tcphdr *tcp;
    int payload_size;
	while ((packet = pcap_next(pcap, &header)) != NULL)
    {
        payload_size = 0;
		process_TCP(packet, header.ts, header.caplen, &ip, &tcp, &payload_size);

        /* Copy 4-tuple connection info to connection structure */
        connection *conn = malloc(sizeof(connection));
        memset(conn, 0, sizeof(connection));
        strncpy(conn->ip_src, inet_ntoa(ip->ip_src), BUFFER_SIZE);
        strncpy(conn->ip_dst, inet_ntoa(ip->ip_dst), BUFFER_SIZE);
        conn->port_src = ntohs(tcp->th_sport);
        conn->port_dst = ntohs(tcp->th_dport);

        /*Add only if the connection is unique */
        if (uniqueConnection(conn, connArray) == 0)
        {
            connArray[totalConnection] = conn;
            totalConnection++;
        }
    }

    printf("A) Total number of connections: %d\n\n", totalConnection);

    printf("B) Connection Details:\n\n");

    struct _generalStatsStruct stats = generalStatsDefault;
    for (int i = 0; i < totalConnection; i++) {
        connection *temp = connArray[i];
        /*Filter by packets for this connection only using 4-tuple */
        char filter_template[] = "ip host %s and ip host %s and port %d and port %d";
        sprintf(filter_exp, filter_template, temp->ip_src, temp->ip_dst, temp->port_src, temp->port_dst);

        pcap = build_filter(argv[0], errbuf, &fp, filter_exp);

        getConnectionInfo(temp, pcap, &stats.totalReset, &header);

        printf("Connection: %d\n", i+1);
        printf("Source Address: %s\n", temp->ip_src);
        printf("Destination Address: %s\n", temp->ip_dst);
        printf("Source Port: %d\n", temp->port_src);
        printf("Destination Port: %d\n", temp->port_dst);

        //Completed and Reset
        char reset = ' ';
        if ((temp->rst_count > 0) &&
            (temp->syn_count > 0) &&
            (temp->fin_count > 0))
        {
            reset = 'R';
        }
        //No control segments after reset
        if ((temp->rst_count > 0) &&
            (temp->syn_count == 0) &&
            (temp->fin_count == 0))
        {
            printf("Status: R\n");
        }
        else
        {
            printf("Status: S%dF%d%c\n", temp->syn_count, temp->fin_count, reset);
        }

        if (temp->fin_count == 0)   stats.openConnection++;

        if ((temp->syn_count >= 1) &&
            (temp->fin_count >= 1))
        {
            stats.completeConnection++;
            printCompleteConnection(temp, &stats, &header);
            computeRTT(temp, &stats);
        }

        printf("END\n");
        printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
        printf("\n");
    }

    printf("C) General\n");
    printf("\n");
    printf("Total number of complete TCP connections: %d\n", stats.completeConnection);
    printf("Number of reset TCP connections: %d\n", stats.totalReset);
    printf("Number of TCP connections that were still open when the trace capture ended: %d\n", stats.openConnection);
    printf("\n");
    printf("D) Complete TCP connections: \n");
    printf("\n");
    printf("Minimum time durations: %f\n", stats.minDuration);
    printf("Mean time durations: %f\n", (double) stats.totalDuration/stats.completeConnection);
    printf("Maximum time durations: %f\n", stats.maxDuration);
    printf("\n");
    printf("Minimum RTT values including both send/received: %f\n", stats.minRTT);
    printf("Mean RTT values including both send/received: %f\n", stats.totalRTT/stats.totalPacket);
    printf("Maximum RTT values including both send/received: %f\n", stats.maxRTT);
    printf("\n");
    printf("Minimum number of packets including both send/received: %d\n", stats.minPacket);
    printf("Mean number of packets including both send/received: %d\n", stats.totalPacket/stats.completeConnection);
    printf("Maximum number of packets including both send/received: %d\n", stats.maxPacket);
    printf("\n");
    printf("Minimum receive window sizes including both send/received: %d\n", stats.minWindow);
    printf("Mean receive window sizes including both send/received: %d\n", stats.totalWindow/stats.totalPacket);
    printf("Maximum receive window sizes including both send/received: %d\n", stats.maxWindow);

	// terminate
	return 0;
}

/* Opens file, compiles and sets filter provided by filter_exp */
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
