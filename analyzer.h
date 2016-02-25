#include <stdlib.h>
#include <limits.h>

#define BUFFER_SIZE 80
#define MAX_NUM_CONNECTION 1000

typedef struct _round_trip {
    uint32_t number;
    struct timeval time;
} round_trip;

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
	double duration;
	int num_packet_src; /* number of packets sent out by source */
	int num_packet_dst; /* number of packets sent out by destination */
	int num_total_packets;
	int cur_data_len_src; /* number of data bytes by source */
	int cur_data_len_dst; /* number of data bytes by destination */
	int cur_total_data_len;
    uint16_t max_win_size;  /*max window size*/
    uint16_t min_win_size;  /*min window size*/
    int sum_win_size;
    round_trip rtt_src_arry[MAX_NUM_CONNECTION/4];
    int rtt_src_arry_len;
    round_trip rtt_dst_arry[MAX_NUM_CONNECTION/4];
    int rtt_dst_arry_len;
} connection;

struct _generalStatsStruct {
    int completeConnection;
    int totalReset;
    int openConnection;

    int minPacket;
    int maxPacket;
    int totalPacket;

    double minDuration;
    double maxDuration;
    double totalDuration;

    uint16_t minWindow;
    uint16_t maxWindow;
    uint32_t totalWindow;
};

const struct _generalStatsStruct generalStatsDefault = {
    0,
    0,
    0,
    INT_MAX,
    0,
    0,
    LONG_MAX,
    0,
    0,
    UINT16_MAX,
    0,
    0
};
