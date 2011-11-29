//
// Test navl connection API's
//
// Usage: ./flowaware <capfile1> [<capfile2>...<capfileN>]
//
// Notes:
//
// 1.) This little program handles tcp & udp packets only. The capture files may
//     contain other protocols but those packets will be ignored.  	
//
// 2.) The navl_conn_classify API assumes it is working with a stream and that
//     the flow of data is in-order. If captured packets are reordered, ymmv.
//

#include <tr1/unordered_map>
#include <pcap.h>
#include <navl.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

using namespace std;
using namespace tr1;

// @conn_key is the connection 5-tuple
struct conn_key
{
	conn_key()
	: src_addr(0), dst_addr(0)
	, src_port(0), dst_port(0)
	, ip_proto(0) {}

	u_int	src_addr;
	u_int	dst_addr;
	u_short	src_port;
	u_short	dst_port;
	u_char	ip_proto;
};

// @conn_info stores details about a connection
struct conn_info
{
	conn_info(conn_key *key)
	: key(*key)
	, conn_id(0)
	, packet_num(0)
	, classified_num(0)
	, class_state(NAVL_STATE_INSPECTING)
	, initiator_total_packets(0)
	, recipient_total_packets(0)
	, initiator_total_bytes(0)
	, recipient_total_bytes(0)
	, dpi_state(0), dpi_result(0)
	, dpi_confidence(0)
	, error(0) {}

	conn_key key;						// Key to lookup associated connection

	u_int	conn_id;					// display only connection id
	u_int	packet_num;					// packet number this was created on
	u_int	classified_num;				// packet number conn was classified on
	navl_state_t class_state;			// classification state


	u_int	initiator_total_packets;	// total packets from initiator
	u_int	recipient_total_packets;	// total packets from recipient

	u_int	initiator_total_bytes;		// total bytes from initiator
	u_int	recipient_total_bytes;		// total bytes from recipient

	void 	*dpi_state;					// navl connection state handle
	u_int	dpi_result;					// results from classification
	int		dpi_confidence;				// confidence level
	int		error;						// error code from classification
};

static void classify_udp(const u_char *ptr, u_int len, conn_key *key, u_int num);
static void classify_tcp(const u_char *ptr, u_int len, conn_key *key, u_int num);

// @conn_key_hasher generates a weak hash from the 5-tuple @conn_key
struct conn_key_hasher
{
	size_t operator()(const conn_key &key) const
	{
		return key.src_addr + key.dst_addr + key.src_port + key.dst_port + key.ip_proto;
	}
};

// @conn_key_equal returns true if 2 @conn_key's match (in either direction)
struct conn_key_equal
{
	bool forward_lookup_4tuple(const conn_key &k1, const conn_key &k2) const
	{
		return 
			k1.src_addr == k2.src_addr &&
			k1.dst_addr == k2.dst_addr &&
			k1.src_port == k2.src_port &&
			k1.dst_port == k2.dst_port;
	}

	bool reverse_lookup_4tuple(const conn_key &k1, const conn_key &k2) const
	{
		return 
			k1.src_addr == k2.dst_addr &&
			k1.dst_addr == k2.src_addr &&
			k1.src_port == k2.dst_port &&
			k1.dst_port == k2.src_port;
	}

	bool operator()(const conn_key &k1, const conn_key &k2) const
	{
		return
			(k1.ip_proto == k2.ip_proto &&
			(forward_lookup_4tuple(k1, k2) || reverse_lookup_4tuple(k1, k2)));
	}
};

// @conn_table maps conn_key -> conn_info (the @conn_key::src_addr always reflects the 
// true connection initiator)
typedef tr1::unordered_map<conn_key, conn_info, conn_key_hasher, conn_key_equal> conn_table;
static conn_table g_conn_table;

// our conn_id for display purposes
static u_int g_last_conn_id = 0;

static const char *
make_ip_addr(u_int ip_addr, char *buf)
{
	sprintf(buf, "%u.%u.%u.%u"
		, ((ip_addr & 0xff000000) >> 24)
		, ((ip_addr & 0x00ff0000) >> 16)
		, ((ip_addr & 0x0000ff00) >> 8)
		, ((ip_addr & 0x000000ff)));
	return buf;
}

static const char *
get_error_string(int error)
{
	switch (error)
	{
	case 0:
		return "None";
	case ENOMEM:
		return "No memory available";
	case ENOBUFS:
		return "No flows available";
	case ENOSR:
		return "No resources available";
	case ENOTCONN:
		return "No connection allocated";
	default:
		return "Unknown";
	}
}

static const char *
get_state_string(navl_state_t state)
{
	switch (state)
	{
	case NAVL_STATE_INSPECTING:
		return "INSPECTING";
	case NAVL_STATE_CLASSIFIED:
		return "CLASSIFIED";
	case NAVL_STATE_TERMINATED:
		return "TERMINATED";
	default:
		return "UNKNOWN";
	}
}


// update packet statistics
//
// @iph_key is the 5-tuple key build from the packet under inspection
// @tbl_key is the 5-tuple key saved in the global connection table
// @conn is the conn_info associated with the @tbl_key
//
void
update_stats(const conn_key *iph_key, const conn_key *tbl_key, conn_info *conn, u_int bytes)
{
	// Track some stats (recall we store the 5-tuple in the original connection initiator's order)
	if (tbl_key->src_addr != iph_key->src_addr)
	{
		conn->recipient_total_packets++;
		conn->recipient_total_bytes += bytes;
	}
	else
	{
		conn->initiator_total_packets++;
		conn->initiator_total_bytes += bytes;
	}
}

// display a connection
void
display_conn(const conn_key *key, const conn_info *info)
{
	static char name[9];
	static char addr_buf[sizeof("xxx.xxx.xxx.xxx")];

	fprintf(stdout, "\n     Connection ID: %u\n", info->conn_id);
	fprintf(stdout, " Started on Packet: %u\n", info->packet_num);
	fprintf(stdout, "    Client Details: %s:%u (%u bytes sent)\n"
		, make_ip_addr(key->src_addr, addr_buf), key->src_port, info->initiator_total_bytes);
	fprintf(stdout, "    Server Details: %s:%u (%u bytes sent)\n"
		, make_ip_addr(key->dst_addr, addr_buf), key->dst_port, info->recipient_total_bytes);

	fprintf(stdout, "    Classification: %s (%s after %u packets %u%% confidence)\n"
		, info->dpi_result 
			? navl_proto_get_name(info->dpi_result, name, sizeof(name)) : "UNKNOWN"
		, get_state_string(info->class_state)
		, info->classified_num 
			? info->classified_num : (info->initiator_total_packets + info->recipient_total_packets)
		, info->dpi_confidence);

	if (info->error)
		fprintf(stdout, "            Error: %s\n", get_error_string(info->error));
}

// callback for navl_conn_classify()
int
navl_conn_classify_callback(navl_result_t result, navl_state_t state, void *arg, int error)
{
	conn_info *info = static_cast<conn_info *>(arg);

	// save any error
	info->error = error;

	// save the classification state
	info->class_state = state;
	
	// fetch the result
	info->dpi_result = navl_app_get(result, &info->dpi_confidence);

	// if we've just classified the connection, record what data packet (sum)
	// the event occur on
	if (!info->classified_num && state == NAVL_STATE_CLASSIFIED)
		info->classified_num = info->initiator_total_packets + info->recipient_total_packets;

	// Remove connections for terminated flows
	if (state == NAVL_STATE_TERMINATED)
	{
		conn_table::iterator it = g_conn_table.find(info->key);
		if (it != g_conn_table.end())
		{
			display_conn(&it->first, &it->second);
			g_conn_table.erase(it);
		}
	}

	return 0;
}

// classify_packet()
//
// @param pkt		pointer to the beginning of an ethernet frame
// @param size		length of the frame pointed to by @pkt
// @param num		packet number in the active capture file
//
void
classify_packet(const u_char *pkt, u_int size, u_int num)
{
	const u_char *ptr = pkt;
	u_int len = size;
	const u_short *eth_type;
	const iphdr *iph;
	conn_key key;

	// Read the first ether type
	len -= 12;
	eth_type = reinterpret_cast<const u_short *>(&ptr[12]);

	// Strip any vlans if present
	while (ntohs(*eth_type) == ETH_P_8021Q)
	{
			eth_type += 2;
			len -= 4;
	}

	// Ignore non-ip packets
	if (ntohs(*eth_type) != ETH_P_IP)
		return;	

	len -= 2;
	iph = reinterpret_cast<const iphdr *>(++eth_type);

	// Do basic sanity of the ip header
	if (iph->ihl < 5 || iph->version != 4 || len < ntohs(iph->tot_len))
		return;	

	// Fix up the length as it may have been padded
	len = ntohs(iph->tot_len);

	// Build the 5-tuple key
	key.ip_proto = iph->protocol;
	key.src_addr = ntohl(iph->saddr);
	key.dst_addr = ntohl(iph->daddr);

	// Find the tcp header offset
	len -= (iph->ihl << 2);
	ptr = reinterpret_cast<const u_char *>(iph) + (iph->ihl << 2);

	switch (iph->protocol)
	{
	case IPPROTO_TCP:
		classify_tcp(ptr, len, &key, num);
		break;
	case IPPROTO_UDP:
		classify_udp(ptr, len, &key, num);
		break;
	};
}

void
classify_udp(const u_char *ptr, u_int len, conn_key *key, u_int num)
{
	conn_info *info;
	const udphdr *uh = reinterpret_cast<const udphdr *>(ptr);

	key->src_port = ntohs(uh->source);
	key->dst_port = ntohs(uh->dest);
	ptr += sizeof(*uh);
	len -= sizeof(*uh);

	conn_table::iterator it = g_conn_table.find(*key);
	if (it == g_conn_table.end())
	{
		std::pair<conn_table::iterator, bool> result = g_conn_table.insert(std::make_pair(*key, conn_info(key)));
		if (!result.second)
		{
			fprintf(stderr, "Error UDP packet %u - failed to allocate state for connection\n", num);
			return;
		}

		it = result.first;

		// Give this connection an identifier
		it->second.conn_id = ++g_last_conn_id;

		// Note which packet caused this connection to be created
		it->second.packet_num = num;

		if (navl_conn_init(key->src_addr, key->src_port, key->dst_addr, key->dst_port
			, key->ip_proto, &(it->second.dpi_state)) != 0)
		{
			g_conn_table.erase(it);
			fprintf(stderr, "Error UDP packet %u - navl_conn_init() failed\n", num);
			return;
		}
	}

	info = &it->second;

	if (len && !info->error)
	{
		// Update packet stats
		update_stats(key, &it->first, info, len);

		// Send only the payload
		if (navl_conn_classify(key->src_addr, key->src_port, key->dst_addr, key->dst_port, key->ip_proto
		, info->dpi_state, ptr, len, navl_conn_classify_callback, (void *)info))
		{
			fprintf(stderr, "Error UDP packet %u - navl_conn_classify() failed\n", num);
		}
	}
}

void
classify_tcp(const u_char *ptr, u_int len, conn_key *key, u_int num)
{
	conn_info *info;
	const tcphdr *th = reinterpret_cast<const tcphdr *>(ptr);

	key->src_port = ntohs(th->source);
	key->dst_port = ntohs(th->dest);
	ptr += (th->doff << 2);
	len -= (th->doff << 2);

	// Retrieve the connection state
	conn_table::iterator it = g_conn_table.find(*key);
	if (it == g_conn_table.end())
	{
		// In order to allocate state, this must be a clean SYN
		if (!th->syn || th->ack)
			return;

		std::pair<conn_table::iterator, bool> result = g_conn_table.insert(std::make_pair(*key, conn_info(key)));
		if (!result.second)
		{
			fprintf(stderr, "Ignoring TCP packet %u - failed to allocate state for connection\n", num);
			return;
		}

		it = result.first;

		// Give this connection an identifier
		it->second.conn_id = ++g_last_conn_id;

		// Note which packet caused this connection to be created
		it->second.packet_num = num;
	}

	// Get a pointer to the state
	info = &(it->second);

	// If we have a syn-ack and no dpi state, setup a new connection.
	if (th->syn && th->ack && !info->dpi_state)
	{
		// Time to tell navl about the connection. The navl library makes the assumption that when a new
		// connection is created it is being created with a 5-tuple reflecting the conversation semantics
		// of the first packet - that is it assumes internally that the @src_addr is infact the connection
		// initiator and the @dst_addr is the connection recipient.
		//
		// In the case here, we are creating the connection on a syn-ack trigger - so the @key reflects the
		// traffic from the server. No problem, just reverse the tuple.
		//
		if (navl_conn_init(key->dst_addr, key->dst_port, key->src_addr, key->src_port
			, key->ip_proto, &info->dpi_state) != 0)
		{
			g_conn_table.erase(it);
			fprintf(stderr, "Error TCP packet %u - navl_conn_init() failed\n", num);
			return;
		}
	}

	// Update packet statistics
	update_stats(key, &it->first, info, len);

	if (len && info->dpi_state && !info->error)
	{
		// Send only the payload
		if (navl_conn_classify(key->src_addr, key->src_port, key->dst_addr, key->dst_port, key->ip_proto
		, info->dpi_state, ptr, len, navl_conn_classify_callback, (void *)info))
			fprintf(stderr, "Error TCP packet %u - navl_conn_classify() failed\n", num);
	}

	// This isn't technically correct because the other side may still be sending data we should be
	// looking at. However for this simple test, its good enough. The logic above should just ignore
	// any remaining packets on this connection.
	if (th->fin || th->rst)
	{
		// If we've initialized this connection, tell navl to free it
		if (info->dpi_state)
		{
			navl_conn_fini(key->src_addr, key->src_port, key->dst_addr, key->dst_port
				, key->ip_proto);
		}

		// Display it
		display_conn(&it->first, &it->second);

		// Cleanup 
		g_conn_table.erase(it);
	}
}

int
main(int argc, char *argv[])
{
	char err[PCAP_ERRBUF_SIZE];
	int idx;

	// Permit a list of capture files to be processed in sequence
	if (argc < 2)
	{
		fprintf(stderr, "%s <capfile1> [<capfile2>...<capfileN>]\n", argv[0]);
		return -1;
	}	

	// While there are files
	for (idx = 1; idx < argc; idx++)
	{
		struct pcap_pkthdr hdr;
		const u_char *data;
		u_int num;

		// Assume a directory named 'plugins' exists in this directory
		//
		if (navl_open(8192, 1, "plugins"))
		{
			fprintf(stderr, "failed to load classification\n");
			exit(0);
		}
		
		// Tell navl to only look at the first http transaction on a persistent http connection
		char buf[10];
		navl_command("classification http persistence set", "1", buf, sizeof(buf)); 

		// Tell navl that it should NOT do any kind of connection life-time management
		navl_conn_idle_timeout(IPPROTO_TCP, 0);
		navl_conn_idle_timeout(IPPROTO_UDP, 0);

		// Enable verbose logging
		navl_command("log level set", "debug", 0, 0);

		// Open the first pcap file. If there's a problem, bail and try the next one.
		//
		pcap_t *pcap = pcap_open_offline(argv[idx], err);
		if (!pcap)
		{
			fprintf(stderr, "failed to open '%s' (%s)\n", argv[idx], err);
			navl_close();
			continue;
		}

		// Try to classify each packet. Only tcp packet are of interest here and all others
		// are simply ignored.
		//
		num = 0;
		while ((data = pcap_next(pcap, &hdr)) != NULL)
			classify_packet(data, hdr.caplen, ++num);

		// Any remaining connection (those we didn't see fin/rst for) will still linger in our
		// conn_table. Display those that remain and cleanup.
		//
		while (!g_conn_table.empty())
		{
			conn_table::iterator it = g_conn_table.begin();
			display_conn(&it->first, &it->second);

			// Tell navl to clean these up
			navl_conn_fini(it->first.src_addr, it->first.src_port, it->first.dst_addr, it->first.dst_port
				, it->first.ip_proto);

			g_conn_table.erase(it);
		}

		// Dump navl diagnostics
//		fprintf(stdout, "\nNAVL DIAG\n");
//		navl_diag(STDOUT_FILENO);

		// Cleanup
		navl_close();
		pcap_close(pcap);
	}

	return 0;
}
