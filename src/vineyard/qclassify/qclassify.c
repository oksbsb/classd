#include <assert.h>	
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <poll.h>
#include <navl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* flag to indicate classification is finished */
#define MARK_CLASSIFY_DONE 0x1000

/* how long to wait for a new packet */
#define POLL_TIME 10

/* portion of mark used for classification */
#define PROTO_MASK 0xfff

int g_shutdown = 0;

/* command line arguments */
unsigned int g_queue_num = 0;
int g_flows = 1024;
const char *g_plugin_dir = NULL;
int g_rerun = 0;

/* container for passing state through callback */
struct callback_info
{
	struct nfq_q_handle *qh;
	struct nfq_data *tb;
};

void qclassify_usage(char *exename)
{
	printf("Usage: %s [-f <flows>] [-q <queue-num>] [-r] [-p <plugin-dir>]\n", exename);
	printf("Optional arguments:\n");
	printf("  -r                  rerun classified packets through iptables filter\n");
	printf("  -f <flows>          maximum number of concurrent flows to classify (default 1024)\n");
	printf("  -q <queue-num>      netfilter queue number to listen on (default 0)\n");
	printf("  -p <plugin-dir>     directory containing classification plugins\n");
	printf("\n");
}

int qclassify_init(int argc, char *argv[])
{
	const char *optstr = "f:q:w:s:c:p:l:L:r";
	int opt;

	g_plugin_dir = "plugins";

	while ((opt = getopt(argc, argv, optstr)) != -1)
	{
		switch (opt)
		{
		case 'f':
			g_flows = atoi(optarg);
			break;
		case 'q':
			g_queue_num = atoi(optarg);
			break;
		case 'p':
			g_plugin_dir = optarg;
			break;
		case 'r':
			g_rerun = 1;
			break;
		default:
			qclassify_usage(argv[0]);
			return 0;
		}
	}

	/* open the navl library */
	if (navl_open(g_flows, 1, g_plugin_dir) == -1)
		return 0;

	return 1;
}

void qclassify_exit()
{
	navl_close();
}

int navl_callback(navl_result_t result, navl_state_t state, void *arg, int error)
{
	/* get the top protocol classification */
	int confidence = 0;
	int proto = navl_app_get(result, &confidence);

	struct callback_info *ci = (struct callback_info *)arg;
	struct nfqnl_msg_packet_hdr *hdr = nfq_get_msg_packet_hdr(ci->tb);
	unsigned int old_mark = nfq_get_nfmark(ci->tb);
	unsigned int new_mark = old_mark | proto;

	if (state != NAVL_STATE_INSPECTING)
		new_mark |= MARK_CLASSIFY_DONE;

	/* this function is deprecated in later versions of libnetfilter_queue, 
		but is the only one we can use in others */
	nfq_set_verdict_mark(ci->qh, 
		hdr ? ntohl(hdr->packet_id) : 0, 
		(proto && g_rerun) ? NF_REPEAT : NF_ACCEPT,
		new_mark, 0, NULL);

	return 0;
}

int my_nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *tb, void *arg)
{
	char *data;
	int datalen = nfq_get_payload(tb, &data);

	if (datalen > 0)
	{
		struct callback_info ci;
		ci.qh = qh;
		ci.tb = tb;
		navl_conn_classify(0, 0, 0, 0, IPPROTO_IP, NULL, data, datalen, navl_callback, &ci);
	}

	return 0;
}

void qclassify_loop()
{
	struct nfq_handle *nfqh;
	struct nfq_q_handle *qh;

	if ((nfqh = nfq_open()) == 0)
		printf("nfq_open failed\n");

	else 
	{
		/* ignore return code for this since it's inconsistent between kernel versions */
		/* see http://www.spinics.net/lists/netfilter/msg42063.html */
		nfq_unbind_pf(nfqh, AF_INET);

		if (nfq_bind_pf(nfqh, AF_INET) < 0)
			printf("nfq_bind_pf failed\n");

		else if ((qh = nfq_create_queue(nfqh, g_queue_num, &my_nfq_callback, NULL)) == 0)
			printf("nfq_create_queue on %u failed\n", g_queue_num);

		else if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
			printf("failed to set NFQNL_COPY_PACKET\n");

		else
		{
			/* get the file descriptor for netlink queue */
			int fd = nfnl_fd(nfq_nfnlh(nfqh));

			int ret;
			char buf[2048];
			struct pollfd pollinfo;

			while (!g_shutdown)
			{
				pollinfo.fd = fd;
				pollinfo.events = POLLIN;

				ret = poll(&pollinfo, 1, POLL_TIME);
				if ((ret < 0) && (errno != EINTR))
				{
					printf("poll error nfq fd %d (%d/%s)", fd, errno, strerror(errno));
					break;
				}

				while ((ret = recv(fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0)
					nfq_handle_packet(nfqh, buf, ret);

				if (ret == -1)
				{
					if (errno == EAGAIN || errno == EINTR || errno == ENOBUFS)
						;
					else
					{
						printf("recv error nfq fd %d (%d/%s)", fd, errno, strerror(errno));
						break;
					}
				}
				else if (ret == 0)
				{
					printf("nfq socket closed");
					break;
				}
			}
		}
	}
}

static void 
qclassify_sigint(int signum)
{
	g_shutdown = 1;
}


/* qclassify program */
int main(int argc, char *argv[])
{
	signal(SIGINT, qclassify_sigint);

	if (qclassify_init(argc, argv))
	{
		qclassify_loop();
		qclassify_exit();
	}

	return 0;
}
