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

#include <pcap.h>

#define BUFFER_SIZE 80

/* Some helper functions, which we define at the end of this file. */

/* Returns a string representation of a timestamp. */
const char *timestamp_string(struct timeval ts);

/* Report a problem with dumping the packet with the given timestamp. */
void problem_pkt(struct timeval ts, const char *reason);

/* Report the specific problem of a packet being too short. */
void too_short(struct timeval ts, const char *truncated_hdr);

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
void process_TCP_packet(const unsigned char *packet, struct timeval ts,
			unsigned int capture_len)
{
	struct ip *ip;
	struct tcphdr *tcp;
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

	ip = (struct ip*) packet;
	IP_header_length = ip->ip_hl * 4;	/* ip_hl is in 4-byte words */

	if (capture_len < IP_header_length)
	{
		/* didn't capture the full IP header including options */
		too_short(ts, "IP header with options");
		return;
	}

	if (ip->ip_p != IPPROTO_TCP)
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

	tcp = (struct tcphdr*) packet;

	//TODO: calculate payload size here

	char *src_addr = malloc(BUFFER_SIZE);
	strncpy(src_addr, inet_ntoa(ip->ip_src), BUFFER_SIZE);

	char *dst_addr = malloc(BUFFER_SIZE);
	strncpy(dst_addr, inet_ntoa(ip->ip_dst), BUFFER_SIZE);

	printf("%s TCP src_addr=%s src_port=%d  dst_addr=%s dst_port=%d\n",
		timestamp_string(ts),
		src_addr,
		ntohs(tcp->th_sport),
		dst_addr,
		ntohs(tcp->th_dport)
	);
}


int main(int argc, char *argv[])
{
	pcap_t *pcap;
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "tcp";	/* The filter expression */
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

	pcap = pcap_open_offline(argv[0], errbuf);
	if (pcap == NULL)
	{
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}

	if(pcap_compile(pcap, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap));
		return(2);
	}

	if (pcap_setfilter(pcap, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap));
		return(2);
	}

	/* Now just loop through extracting packets as long as we have
	 * some to read.
	 */
	while ((packet = pcap_next(pcap, &header)) != NULL)
		process_TCP_packet(packet, header.ts, header.caplen);

	// terminate
	return 0;
}


/* Note, this routine returns a pointer into a static buffer, and
 * so each call overwrites the value returned by the previous call.
 */
const char *timestamp_string(struct timeval ts)
{
	static char timestamp_string_buf[256];

	sprintf(timestamp_string_buf, "%d.%06d",
		(int) ts.tv_sec, (int) ts.tv_usec);

	return timestamp_string_buf;
}

void problem_pkt(struct timeval ts, const char *reason)
{
	fprintf(stderr, "%s: %s\n", timestamp_string(ts), reason);
}

void too_short(struct timeval ts, const char *truncated_hdr)
{
	fprintf(stderr, "packet with timestamp %s is truncated and lacks a full %s\n",
		timestamp_string(ts), truncated_hdr);
}
