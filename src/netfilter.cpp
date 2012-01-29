// NETFILTER.CPP
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
// vars for netfilter interfaces
struct nfq_q_handle		*nfqqh;
struct nfq_handle		*nfqh;
/*--------------------------------------------------------------------------*/
void* netfilter_thread(void *arg)
{
struct pollfd	tester;
sigset_t		sigset;
char			*buffer;
int				netsock;
int				val,ret;

sysmessage(LOG_INFO,"The netfilter thread is starting\n");

// set the itimer value of the main thread which is required
// for gprof to work properly with multithreaded applications
setitimer(ITIMER_PROF,&g_itimer,NULL);

// start by masking all signals
sigfillset(&sigset);
pthread_sigmask(SIG_BLOCK,&sigset,NULL);

// now we allow only the PROF signal
sigemptyset(&sigset);
sigaddset(&sigset,SIGPROF);
pthread_sigmask(SIG_UNBLOCK,&sigset,NULL);

// allocate our packet buffer
buffer = (char *)malloc(cfg_net_buffer);

// call our netfilter startup function
ret = netfilter_startup();

	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from netfilter_startup()\n",ret);
	g_shutdown = 1;
	return(NULL);
	}

// get the socket descriptor for the netlink queue
netsock = nfnl_fd(nfq_nfnlh(nfqh));

	// set the socket receive buffer size if config value is not zero
	if (cfg_sock_buffer != 0)
	{
	val = cfg_sock_buffer;
	ret = setsockopt(netsock,SOL_SOCKET,SO_RCVBUF,&val,sizeof(val));

		if (ret != 0)
		{
		sysmessage(LOG_ERR,"Error %d returned from setsockopt(SO_RCVBUF)\n",errno);
		g_shutdown = 1;
		return(NULL);
		}
	}

// set up the poll structure
tester.fd = netsock;
tester.events = POLLIN;
tester.revents = 0;

	while (g_shutdown == 0)
	{
	// wait for data on the socket
	ret = poll(&tester,1,1000);

	// nothing received so just continue
	if (ret == 0) continue;

		// handle poll errors
		if (ret < 0)
		{
		if (errno == EINTR) continue;
		sysmessage(LOG_ERR,"Error %d (%s) returned from poll()\n",errno,strerror(errno));
		break;
		}

		do
		{
		// read from the netfilter socket
		ret = recv(netsock,buffer,cfg_net_buffer,MSG_DONTWAIT);

			if (ret == 0)
			{
			sysmessage(LOG_ERR,"The netfilter socket was unexpectedly closed\n");
			g_shutdown = 1;
			break;
			}

			if (ret < 0)
			{
			if ((errno == EAGAIN) || (errno == EINTR) || (errno == ENOBUFS)) break;
			sysmessage(LOG_ERR,"Error %d (%s) returned from recv()\n",errno,strerror(errno));
			g_shutdown = 1;
			break;
			}

		// pass the data to the packet handler
		nfq_handle_packet(nfqh,buffer,ret);
		} while (ret > 0);
	}

// call our netfilter shutdown function
netfilter_shutdown();

// free our packet buffer memory
free(buffer);

sysmessage(LOG_INFO,"The netfilter thread has terminated\n");
return(NULL);
}
/*--------------------------------------------------------------------------*/
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data)
{
MessageWagon					*local;
struct nfqnl_msg_packet_hdr		*hdr;
unsigned char					*rawpkt;
struct iphdr					*iphead;
int								rawlen;

// first set the accept verdict on the packet
hdr = nfq_get_msg_packet_hdr(nfad);
nfq_set_verdict(qh,(hdr ? ntohl(hdr->packet_id) : 0),NF_ACCEPT,0,NULL);

// get the packet length and data
rawlen = nfq_get_payload(nfad,(char **)&rawpkt);

	// ignore packets with invalid length
	if (rawlen < (int)sizeof(struct iphdr))
	{
	sysmessage(LOG_WARNING,"Invalid length %d received\n",rawlen);
	return(0);
	}

// use the iphdr structure for parsing
iphead = (iphdr *)rawpkt;

// ignore everything except IPv4
if (iphead->version != 4) return(0);

// we only care about TCP and UDP
if ((iphead->protocol != IPPROTO_TCP) && (iphead->protocol != IPPROTO_UDP)) return(0);

// check our special ignore flags
if ((iphead->protocol == IPPROTO_TCP) && (g_skiptcp != 0)) return(0);
if ((iphead->protocol == IPPROTO_UDP) && (g_skipudp != 0)) return(0);

// increment the packet counter
pkt_totalcount++;

	// if classification thread is not enabled then we
	// process the packet right here right now
	if (cfg_packet_thread == 0)
	{
	process_packet(rawpkt,rawlen);
	}

	// otherwise push the packet onto the message queue
	else
	{
	local = new MessageWagon(MSG_PACKET,rawpkt,rawlen);
	g_messagequeue->PushMessage(local);
	}

return(0);
}
/*--------------------------------------------------------------------------*/
int netfilter_startup(void)
{
int		ret;

//open a new netfilter queue handler
nfqh = nfq_open();

	if (nfqh == NULL)
	{
	sysmessage(LOG_ERR,"Error returned from nfq_open()\n");
	g_shutdown = 1;
	return(1);
	}

// unbind any existing queue handler
ret = nfq_unbind_pf(nfqh,AF_INET);

	if (ret < 0)
	{
	sysmessage(LOG_ERR,"Error returned from nfq_unbind_pf()\n");
	g_shutdown = 1;
	return(2);
	}

// bind the queue handler for AF_INET
ret = nfq_bind_pf(nfqh,AF_INET);

	if (ret < 0)
	{
	sysmessage(LOG_ERR,"Error returned from nfq_bind_pf(lan)\n");
	g_shutdown = 1;
	return(3);
	}

// create a new netfilter queue
nfqqh = nfq_create_queue(nfqh,cfg_net_queue,&netq_callback,NULL);

	if (nfqqh == 0)
	{
	sysmessage(LOG_ERR,"Error returned from nfq_create_queue(%u)\n",cfg_net_queue);
	g_shutdown = 1;
	return(4);
	}

// set the queue length
ret = nfq_set_queue_maxlen(nfqqh,cfg_net_maxlen);

	if (ret < 0)
	{
	sysmessage(LOG_ERR,"Error returned from nfq_set_queue_maxlen(%d)\n",cfg_net_maxlen);
	g_shutdown = 1;
	return(5);
	}

// set the queue data copy mode
ret = nfq_set_mode(nfqqh,NFQNL_COPY_PACKET,cfg_net_buffer);

	if (ret < 0)
	{
	sysmessage(LOG_ERR,"Error returned from nfq_set_mode(NFQNL_COPY_PACKET)\n");
	g_shutdown = 1;
	return(6);
	}

return(0);
}
/*--------------------------------------------------------------------------*/
void netfilter_shutdown(void)
{
// destroy the netfilter queue
nfq_destroy_queue(nfqqh);

// shut down the netfilter queue handler
nfq_close(nfqh);
}
/*--------------------------------------------------------------------------*/

