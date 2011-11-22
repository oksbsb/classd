#include <navl.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif

#define ENOSR 63

/* types */
typedef char pcap_msg_t[PCAP_ERRBUF_SIZE];
typedef struct
{
	u_int packets;
	u_long bytes;
} capreader_stats_t;

/* totals */
u_int g_packets = 0;
u_long g_bytes = 0;
u_int g_conns = 0;

pcap_t *g_pcap = NULL;
pcap_msg_t g_pcap_msg;
capreader_stats_t *g_capreader_stats;

int g_conn_id_attr = 0;
int g_maxproto = -1;
u_int g_easyapi = 0;
u_int g_running = 1;
u_int g_verbose = 0;
u_int g_inspect = 0;
u_int g_realtime = 2;
u_int g_flownum = 1024;
char *g_plugins = "plugins";
char *g_exename = NULL;
char *g_capfile = NULL;

static void capreader_init(int argc, char *argv[]);
static void capreader_loop(void);
static void capreader_exit(void);
static void capreader_sigint(int);
static void capreader_sigsegv(int);
static void capreader_results(void);
static void capreader_usage(void);

#define capreader_error() \
do { \
	fprintf(stderr, "%s failed in %s:%u", g_exename, __FUNCTION__, __LINE__); \
	capreader_exit(); \
} while (0)

/* capreader program */
int main(int argc, char *argv[])
{
	signal(SIGINT, capreader_sigint);
	signal(SIGSEGV, capreader_sigsegv);

	capreader_init(argc, argv);
	capreader_loop();
	capreader_exit();

	return 0;
}

static void 
capreader_sigint(int signum)
{
	g_running = 0;
}

static void 
capreader_sigsegv(int signum)
{
	int fd = open("dump.out", O_CREAT | O_WRONLY);
	navl_backtrace(fd);
	close(fd);
	abort();
}

static void
capreader_usage(void)
{
	printf("Usage: %s [OPTION...] filename\n", g_exename);
	printf("  -c      classify traffic\n");
	printf("  -f<num> number of concurrent flows to track (default: %u)\n", g_flownum);
	printf("  -p<dir> plugin directory (default: %s)\n", g_plugins);
	printf("  -r<num> realtime mode - 0=off, 1=real, 2=simulated(default)\n");
	printf("  -s      uses simple classification api (-c is implicit)\n");
	printf("  -v      verbose output\n");
	exit(0);
}

static void
capreader_init(int argc, char *argv[])
{
	int c;

	g_exename = argv[0];
	while ((c = getopt(argc, argv, "cf:p:r:stv")) != -1)
	{
		switch (c)
		{
		case 'c':
			g_inspect = 1;
			break;
		case 'f':
			g_flownum = atoi(optarg);
			break;
		case 'p':
			g_plugins = optarg;
			break;
		case 's':
			g_easyapi = 1;
			g_inspect = 1;
			break;
		case 'r':
			g_realtime = atoi(optarg);
			break;
		case 'v':
			g_verbose = 1;
			break;
		default:
			capreader_usage();
		}
	}

	if (optind >= argc)
		capreader_usage();

	g_capfile = argv[optind];

	/* open the navl library */
	if (navl_open(g_flownum, 1, g_plugins) == -1)
		capreader_error();

	/* lookup the key for conn.id */
	if ((g_conn_id_attr = navl_attr("conn.id", 1)) == -1)
		capreader_error();

	if (g_realtime == 2)
		navl_set_clock_mode(1);

	/* determine the max protocol id */
	g_maxproto = navl_proto_max_id();
	if (g_maxproto == -1)
		capreader_error();

	/* allocate a vector for protocol statistics */
	if (g_maxproto > 0)
	{
		g_capreader_stats = malloc(sizeof(capreader_stats_t) * (g_maxproto + 1));
		if (!g_capreader_stats)
			capreader_error();

		memset(g_capreader_stats, 0, sizeof(capreader_stats_t) * (g_maxproto + 1));
	}

	g_pcap_msg[0] = '\0';
	if ((g_pcap = pcap_open_offline(g_capfile, g_pcap_msg)) == NULL)
		capreader_error();
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

static const char *
get_confidence_string(int confidence)
{
	switch (confidence)
	{
	case 50:
		return "PORT";
	case 100:
		return "DPI";
	default:
		return "NONE";
	}
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

static int
capreader_callback(navl_result_t result, navl_state_t state, void *arg, int error)
{
	int idx, appid, protoid;
	u_int caplen;
	u_int connid;
	char name[9];
	char buf[256];
	navl_iterator_t it;

	caplen = *(u_int *)arg;
	connid = 0;
	int confidence;

	/* Count this packet towards the classified application */
	appid = navl_app_get(result, &confidence);
	g_capreader_stats[appid].packets++;
	g_capreader_stats[appid].bytes += caplen;

	if (g_verbose)
	{
		/* Build the stack string */
		for (idx = 0, it = navl_proto_first(result); navl_proto_valid(it); navl_proto_next(it))
		{
			/* Fetch the ip connid if this protocol id is IP
			 *
			 * Note that as an optimization, the results from navl_proto_find_id() could be
			 * cached to avoid the GUID string lookup.
			 */
			if ((protoid = navl_proto_get_id(it)) == navl_proto_find_id("IP"))
				navl_attr_get(it, g_conn_id_attr, &connid, sizeof(connid));

			if (connid > g_conns)
				g_conns = connid;

			idx += sprintf(&buf[idx], "/%s", navl_proto_get_name(protoid, name, sizeof(name)));
		}
		printf(" Pkt: %u (%d bytes), Conn: %u, App: %s (%s), State: %s, Stack: %s, Error: %s\n", g_packets, caplen, connid,
			navl_proto_get_name(appid, name, sizeof(name)), 
			get_confidence_string(confidence), 
			get_state_string(state), 
			buf,
			get_error_string(error));
	}

	/* Continue tracking the flow */
	return 0;
}

static u_long
msec_time(struct timeval *tv)
{
	return (tv->tv_sec * 1000) + (tv->tv_usec / 1000);
}

static void
msec_delay(u_int msecs)
{
    struct timeval tv = { msecs / 1000, (msecs % 1000) * 1000 };
    select(0, 0, 0, 0, &tv);
}

static void
capreader_loop(void)
{
	struct pcap_pkthdr hdr;
	const u_char *data;
	u_int proto = 0;
	u_long last = 0;
	u_long next = 0;

	while (g_running) 
	{
		if ((data = pcap_next(g_pcap, &hdr)) != NULL)
		{
			g_packets++;
			g_bytes += hdr.caplen;
			proto = 0;

			/* "real" realtime */
			if (g_realtime == 1)
			{
				next = msec_time(&hdr.ts);
				if (last)
					msec_delay(next - last);
				last = next;
			}
			/* simulated realtime */
			else if (g_realtime == 2)
				navl_set_clock(msec_time(&hdr.ts));

			if (g_inspect)
			{
				if (g_easyapi)
				{
					/* Program invoked with the -s switch. Classification is via 
 					 * navl_classify_simple() API. The top (most specific) protocol 
 					 * id is returned in the @proto param. */

					navl_classify_simple(data, hdr.caplen, &proto);
					g_capreader_stats[proto].packets++;
					g_capreader_stats[proto].bytes += hdr.caplen;
				}
				else
				{
					/* Default (not -s switch) mode. Classification is via navl_classify().
					 * Results of classification are gathered in capreader_callback(). */

					navl_classify(data, hdr.caplen, capreader_callback, &hdr.caplen);
				}
			}
		}
		else
			break;
	}
}

static void 
capreader_exit(void)
{
	if (g_pcap)
		pcap_close(g_pcap);

	if (g_capreader_stats)
	{
		capreader_results();
		free(g_capreader_stats);
	}

	navl_close();
	exit(0);
}

static void
capreader_results(void)
{
	u_int idx;
	char name[9];

	if (g_packets == 0)
	{
		printf("\n No packets captured.\n");
		return;
	}

	if (g_inspect)
	{
		printf("\n AppProto    Packets     Bytes");
		printf("\n --------------------------------\n");

		for (idx = 1; idx <= g_maxproto; idx++)
		{
			if (g_capreader_stats[idx].packets)
			{
				/* We need to provide protocol definitions */	
				printf(" %-12s%-12u%lu\n", navl_proto_get_name(idx, name, sizeof(name)), g_capreader_stats[idx].packets, g_capreader_stats[idx].bytes);
			}
		}
	}

	printf("\n %u packets captured (%lu bytes)\n", g_packets, g_bytes);

	if (g_inspect)
	{
		/* report number of connections */
		if (g_conns)
			printf(" %u connections tracked\n", g_conns);
	}

	printf("\n");
}
