Build with:
    make
Run with:
    ./tcp_analyzer capfile

Program Architecture:
The program starts by opening the given pcap file and applying a filter,
that allows SYN only packets. Then, the number of connections are calculated.
A connection struct resides in "analyzer.h" that holds all the relevant information about
a connection such as Source IP, Destination IP, Source Port, Destination Port,
number of packets sent out by source/destination etc.
After we know the number of connections, a connection array is created.
The previously filtered pcap file is read once again and a new connection is
created for every unique 4-tuple(Source IP, Destination IP, Source Port, Destination Port).

Then a loop goes through each connection in the connection array. Here a new filter
is used where the pcap file is filtered by 4-tuple so any packets that belong to
that connection only shows up. Then, the getConnectionInfo() loops through
each packet and calls the process_TCP() function that breaks down the packet into
tcp and ip struct. Any relevant information such as starting time, number of packets
sent/received by source and destination, windows sizes are gathered here and stored
back in the connection struct. This function also resets the structure, in case the
RST bit is set so that only future information is used for calculating statistics.

After, all relevant information for that particular connection is gathered, the
4-tuples are printed out. If the connection has a complete state (i.e. S1F1, S2F1, S2F2),
then the connection is considered complete. The printCompleteConnection()
function is then called which checks if the current values are the min or max packet, window sizes etc
for the overall connection to print out general statistics later. It also calculates the duration, packet number
and data bytes statistics and prints them out.

After all connections are looped through, the stats struct is printed out which
consists of all min, max and total duration, packet etc. i.e. the General statistics.

NOTE:
According to the announcement, when a completed connection has been reset,
it is counted as both completed and R.
If no control segments after reset, the connection is labelled as R.
If an incomplete connection is reset, the whole struct is reset. So, future control
segments determine their completeness.
