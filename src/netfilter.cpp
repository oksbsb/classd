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
struct nfct_handle		*nfcth;
struct nfq_handle		*nfqh;
/*--------------------------------------------------------------------------*/
void* netfilter_thread(void *arg)
{
struct pollfd			pollinfo;
char					buffer[2048];
int						fd,ret;

sysmessage(LOG_INFO,"The netfilter thread is starting\n");

// set the itimer value of the main thread which is required
// for gprof to work properly with multithreaded applications
setitimer(ITIMER_PROF,&g_itimer,NULL);

// call our netfilter startup function
ret = netfilter_startup();

	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from netfilter_startup()\n",ret);
	g_shutdown = 1;
	return(NULL);
	}

// get the file descriptor for netlink queue
fd = nfnl_fd(nfq_nfnlh(nfqh));

	while (g_shutdown == 0)
	{
	pollinfo.fd = fd;
	pollinfo.events = POLLIN;
	pollinfo.revents = 0;

	// wait for data
	ret = poll(&pollinfo,1,1000);

	// nothing received
	if (ret < 1) continue;

		if ((ret < 0) && (errno != EINTR))
		{
		sysmessage(LOG_ERR,"Error %d (%s) returned from poll()\n",errno,strerror(errno));
		break;
		}

	// process the data
	while ((ret = recv(fd,buffer,sizeof(buffer),MSG_DONTWAIT)) > 0) nfq_handle_packet(nfqh,buffer,ret);

		if (ret == -1)
		{
		if (errno == EAGAIN || errno == EINTR || errno == ENOBUFS) continue;
		sysmessage(LOG_ERR,"Error %d (%s) returned from recv()\n",errno,strerror(errno));
		break;
		}

		else if (ret == 0)
		{
		sysmessage(LOG_ERR,"The nfq socket was unexpectedly closed\n");
		g_shutdown = 1;
		break;
		}
	}

// call our netfilter shutdown function
netfilter_shutdown();

sysmessage(LOG_INFO,"The netfilter thread has terminated\n");
return(NULL);
}
/*--------------------------------------------------------------------------*/
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data)
{
MessageWagon					*local;
struct nfqnl_msg_packet_hdr		*hdr;
struct nf_conntrack				*ct;
unsigned char					*rawpkt;
struct xxphdr					*xxphead;
struct iphdr					*iphead;
int								rawlen;
int								ret;

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

// use a generic header for source and dest ports
xxphead = (struct xxphdr *)&rawpkt[iphead->ihl << 2];

// allocate a new conntrack
ct = nfct_new();
if (ct == NULL) return(0);

// setup and submit the conntrack query
nfct_set_attr_u8(ct,ATTR_L3PROTO,AF_INET);
nfct_set_attr_u8(ct,ATTR_L4PROTO,iphead->protocol);
nfct_set_attr_u32(ct,ATTR_IPV4_SRC,iphead->saddr);
nfct_set_attr_u16(ct,ATTR_PORT_SRC,xxphead->source);
nfct_set_attr_u32(ct,ATTR_IPV4_DST,iphead->daddr);
nfct_set_attr_u16(ct,ATTR_PORT_DST,xxphead->dest);
ret = nfct_query(nfcth,NFCT_Q_GET,ct);

// cleanup the conntrack
nfct_destroy(ct);

	// if classification thread is not enabled then we
	// process the packet right here... right now
	if ((cfg_packet_thread | g_splitter) == 0)
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
int conn_callback(enum nf_conntrack_msg_type type,struct nf_conntrack *ct,void *data)
{
LookupObject	*lookup;
uint32_t		orig_saddr,repl_saddr;
uint32_t		orig_daddr,repl_daddr;
uint16_t		orig_sport,repl_sport;
uint16_t		orig_dport,repl_dport;
uint8_t			orig_proto,repl_proto;
uint32_t		sess_id;
const char		*pname;
char			orig_sname[32],repl_sname[32];
char			orig_dname[32],repl_dname[32];
char			namestr[256];
char			finder[64];

orig_proto = nfct_get_attr_u8(ct,ATTR_ORIG_L4PROTO);
repl_proto = nfct_get_attr_u8(ct,ATTR_REPL_L4PROTO);

	if (orig_proto != repl_proto)
	{
	sysmessage(LOG_WARNING,"Protocol mismatch %d != %d in conntrack handler\n",orig_proto,repl_proto);
	return(NFCT_CB_CONTINUE);
	}

if (orig_proto == IPPROTO_TCP) pname = "TCP";
if (orig_proto == IPPROTO_UDP) pname = "UDP";

orig_saddr = nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC);
orig_sport = nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC);
orig_daddr = nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_DST);
orig_dport = nfct_get_attr_u16(ct,ATTR_ORIG_PORT_DST);
repl_saddr = nfct_get_attr_u32(ct,ATTR_REPL_IPV4_SRC);
repl_sport = nfct_get_attr_u16(ct,ATTR_REPL_PORT_SRC);
repl_daddr = nfct_get_attr_u32(ct,ATTR_REPL_IPV4_DST);
repl_dport = nfct_get_attr_u16(ct,ATTR_REPL_PORT_DST);
sess_id = nfct_get_attr_u16(ct,ATTR_ID);

// extract the client and server addresses
inet_ntop(AF_INET,&orig_saddr,orig_sname,sizeof(orig_sname));
inet_ntop(AF_INET,&orig_daddr,orig_dname,sizeof(orig_dname));
inet_ntop(AF_INET,&repl_saddr,repl_sname,sizeof(repl_sname));
inet_ntop(AF_INET,&repl_daddr,repl_dname,sizeof(repl_dname));

sprintf(finder,"%s-%s:%u-%s:%u",pname,repl_sname,ntohs(repl_sport),repl_dname,ntohs(repl_dport));

logmessage(CAT_FILTER,LOG_DEBUG,"TRACKER SEARCH %s\n",finder);
lookup = dynamic_cast<LookupObject*>(g_lookuptable->SearchObject(finder));

	if (lookup == NULL)
	{
	lookup = new LookupObject(orig_proto,finder);
	lookup->UpdateObject(orig_saddr,orig_sport,orig_daddr,orig_dport);
	lookup->GetObjectString(namestr,sizeof(namestr));
	logmessage(CAT_FILTER,LOG_DEBUG,"TRACKER INSERT %s\n",namestr);
	g_lookuptable->InsertObject(lookup);
	}

	else
	{
	lookup->UpdateObject(orig_saddr,orig_sport,orig_daddr,orig_dport);
	lookup->GetObjectString(namestr,sizeof(namestr));
	logmessage(CAT_FILTER,LOG_DEBUG,"TRACKER UPDATE %s\n",namestr);
	}

return(NFCT_CB_CONTINUE);
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

// set the queue data copy mode
ret = nfq_set_mode(nfqqh,NFQNL_COPY_PACKET,0xFFFF);

	if (ret < 0)
	{
	sysmessage(LOG_ERR,"Error returned from nfq_set_mode(NFQNL_COPY_PACKET)\n");
	g_shutdown = 1;
	return(5);
	}

// open a conntrack netlink handler
nfcth = nfct_open(CONNTRACK,NFNL_SUBSYS_CTNETLINK);

	if (nfcth == NULL)
	{
	sysmessage(LOG_ERR,"Error %d returned from nfct_open()\n",errno);
	g_shutdown = 1;
	return(6);
	}

// register the conntrack callback
ret = nfct_callback_register(nfcth,NFCT_T_ALL,conn_callback,NULL);

	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from nfct_callback_register()\n",errno);
	g_shutdown = 1;
	return(7);
	}

return(0);
}
/*--------------------------------------------------------------------------*/
void netfilter_shutdown(void)
{
// unregister the callback handler
nfct_callback_unregister(nfcth);

// close the conntrack netlink handler
nfct_close(nfcth);

// destroy the netfilter queue
nfq_destroy_queue(nfqqh);

// shut down the netfilter queue handler
nfq_close(nfqh);
}
/*--------------------------------------------------------------------------*/

