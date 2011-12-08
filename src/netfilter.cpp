// NETFILTER.C
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data);
int navl_callback(navl_result_t result,navl_state_t state,void *arg,int error);
void netfilter_shutdown(void);
int netfilter_startup(void);
/*--------------------------------------------------------------------------*/
// vars for all of the protocol and application id values
static int l_proto_eth = 0;
static int l_proto_ip = 0;
static int l_proto_tcp = 0;
static int l_proto_udp = 0;
static int l_proto_http = 0;
static int l_proto_ssl = 0;
static int l_proto_sip = 0;
static int l_proto_ctrxica = 0;
static int l_proto_fbookapp = 0;
static int l_proto_ymsgfile = 0;

// vars for the dynamic attributes we use
static int l_attr_tcp_sport = 0;
static int l_attr_tcp_dport = 0;
static int l_attr_udp_sport = 0;
static int l_attr_udp_dport = 0;
static int l_attr_ip_saddr = 0;
static int l_attr_ip_daddr = 0;
static int l_attr_conn_id = 0;
static int l_attr_fbook_app = 0;
static int l_attr_tls_host = 0;
static int l_attr_http_info = 0;

// vars for our netfilter queue
struct nfq_handle *nfqh;
/*--------------------------------------------------------------------------*/
void* netfilter_thread(void *arg)
{
struct nfq_q_handle		*qh;
struct pollfd			pollinfo;
char					buffer[2048];
int						fd,ret;

logmessage(LOG_INFO,"The netfilter thread is starting\n");

// set the itimer value of the main thread which is required
// for gprof to work properly with multithreaded applications
setitimer(ITIMER_PROF,&g_itimer,NULL);

// call the main startup function
ret = netfilter_startup();

	if (ret != 0)
	{
	logmessage(LOG_ERR,"Error %d returned from netfilter_startup()\n",ret);
	g_shutdown = 1;
	return(NULL);
	}

// create a new queue handler
qh = nfq_create_queue(nfqh,cfg_net_queue,&netq_callback,NULL);

	if (qh == 0)
	{
	logmessage(LOG_ERR,"Error returned from nfq_create_queue(%u)\n",cfg_net_queue);
	g_shutdown = 1;
	return(NULL);
	}

// set the queue data copy mode
ret = nfq_set_mode(qh,NFQNL_COPY_PACKET,0xFFFF);

	if (ret < 0)
	{
	logmessage(LOG_ERR,"Error returned from nfq_set_mode(NFQNL_COPY_PACKET)\n");
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
		logmessage(LOG_ERR,"Error %d (%s) returned from poll()\n",errno,strerror(errno));
		break;
		}

	// process the data
	while ((ret = recv(fd,buffer,sizeof(buffer),MSG_DONTWAIT)) > 0) nfq_handle_packet(nfqh,buffer,ret);

		if (ret == -1)
		{
		if (errno == EAGAIN || errno == EINTR || errno == ENOBUFS) continue;
		logmessage(LOG_ERR,"Error %d (%s) returned from recv()\n",errno,strerror(errno));
		break;
		}

		else if (ret == 0)
		{
		logmessage(LOG_ERR,"The nfq socket was unexpectedly closed\n");
		g_shutdown = 1;
		break;
		}
	}

// destroy the netfilter queue
nfq_destroy_queue(qh);

// call the main shutdown function
netfilter_shutdown();

logmessage(LOG_INFO,"The netfilter thread has terminated\n");
return(NULL);
}
/*--------------------------------------------------------------------------*/
int navl_callback(navl_result_t result,navl_state_t state,void *arg,int error)
{
struct in_addr					saddr,daddr;
navl_iterator_t					it;
HashObject						*local;
u_short							sport,dport;
int								confidence,ipproto;
int								appid,value;
int								ret,idx;
char							application[32];
char							protochain[256];
char							detail[256];
char							finder[64];
char							srcaddr[32];
char							dstaddr[32];
char							xtra[256];
char							work[32];

application[0] = 0;
protochain[0] = 0;
detail[0] = 0;
confidence = 0;
ipproto = 0;
idx = 0;

	// keep track of errors returned by vineyard
	if (error != 0) switch (error)
	{
	case ENOMEM:	err_nomem++;	break;
	case ENOBUFS:	err_nobufs++;	break;
	case ENOSR:		err_nosr++;		break;
	case ENOTCONN:	err_notconn++;	break;
	default:		err_unknown++;	break;
	}

// get the application and confidence
appid = navl_app_get(result,&confidence);
navl_proto_get_name(appid,application,sizeof(application));

	// build the protochain grabbing extra info for certain protocols
	for(it = navl_proto_first(result);navl_proto_valid(it);navl_proto_next(it))
	{
	value = navl_proto_get_id(it);

		// get the source and destination address for all IP packets
		if (value == l_proto_ip)
		{
		navl_attr_get(it,l_attr_ip_saddr,&saddr.s_addr,sizeof(saddr.s_addr));
		navl_attr_get(it,l_attr_ip_daddr,&daddr.s_addr,sizeof(daddr.s_addr));
		}

		// get the source and destination port for all TCP packets
		if (value == l_proto_tcp)
		{
		navl_attr_get(it,l_attr_tcp_sport,&sport,sizeof(sport));
		navl_attr_get(it,l_attr_tcp_dport,&dport,sizeof(dport));
		ipproto = IPPROTO_TCP;
		}

		// get the source and destination port for all UDP packets
		if (value == l_proto_udp)
		{
		navl_attr_get(it,l_attr_udp_sport,&sport,sizeof(sport));
		navl_attr_get(it,l_attr_udp_dport,&dport,sizeof(dport));
		ipproto = IPPROTO_UDP;
		}

		// get the content type for HTTP connections
		if (value == l_proto_http)
		{
		ret = navl_attr_get(it,l_attr_http_info,xtra,sizeof(xtra));
		if (ret == 0) strcpy(detail,xtra);
		}

		// get the application name for facebook apps
		if (value == l_proto_fbookapp)
		{
		ret = navl_attr_get(it,l_attr_fbook_app,xtra,sizeof(xtra));
		if (ret == 0) strcpy(detail,xtra);
		}

		// get the cert name for SSL connections
		if (value == l_proto_ssl)
		{
		ret = navl_attr_get(it,l_attr_tls_host,xtra,sizeof(xtra));
		if (ret == 0) strcpy(detail,xtra);
		}

	// append the protocol name to the chain
	work[0] = 0;
	navl_proto_get_name(value,work,sizeof(work));
	idx+=sprintf(&protochain[idx],"/%s",work);
	}

// only TCP or UDP packets will set this flag allowing
// us to ignore all other unknown protocol values
if (ipproto == 0) return(0);

saddr.s_addr = htonl(saddr.s_addr);
daddr.s_addr = htonl(daddr.s_addr);
strcpy(srcaddr,inet_ntoa(saddr));
strcpy(dstaddr,inet_ntoa(daddr));

// try the inverted lookup first
if (ipproto == IPPROTO_TCP) sprintf(finder,"TCP-%s:%d-%s:%d",dstaddr,dport,srcaddr,sport);
if (ipproto == IPPROTO_UDP) sprintf(finder,"UDP-%s:%d-%s:%d",dstaddr,dport,srcaddr,sport);

// search the hash table for the entry
logmessage(LOG_DEBUG,"SEARCHING INVERT %s\n",finder);
local = g_conntable->SearchObject(finder);

	if (local == NULL)
	{
	if (ipproto == IPPROTO_TCP) sprintf(finder,"TCP-%s:%d-%s:%d",srcaddr,sport,dstaddr,dport);
	if (ipproto == IPPROTO_UDP) sprintf(finder,"UDP-%s:%d-%s:%d",srcaddr,sport,dstaddr,dport);

	// search the hash table for the entry
	logmessage(LOG_DEBUG,"SEARCHING NORMAL %s\n",finder);
	local = g_conntable->SearchObject(finder);
	}

	// not found so create new object in hashtable
	if (local == NULL)
	{
	logmessage(LOG_DEBUG,"INSERT %s [%s|%s|%s|%d|%d]\n",finder,application,protochain,detail,confidence,state);
	local = new HashObject(ipproto,finder,application,protochain,detail,confidence,state);
	ret = g_conntable->InsertObject(local);
	}

	// existing session so update the object
	else
	{
	logmessage(LOG_DEBUG,"UPDATE %s [%s|%s|%s|%d|%d]\n",finder,application,protochain,detail,confidence,state);
	local->UpdateObject(application,protochain,detail,confidence,state);
	}

	// clean up terminated connections
	if (state == NAVL_STATE_TERMINATED)
	{
	logmessage(LOG_DEBUG,"REMOVE %s\n",finder);
	ret = g_conntable->DeleteObject(finder);
	return(0);
	}

// continue tracking the flow
return(0);
}
/*--------------------------------------------------------------------------*/
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data)
{
struct nfqnl_msg_packet_hdr		*hdr;
uint16_t						sport,dport;
uint32_t						saddr,daddr;
unsigned char					*pkt;
const tcphdr					*tcphead;
const udphdr					*udphead;
const iphdr						*iphead;
const char						*pname;
char							sname[32];
char							dname[32];
char							finder[64];
int								len;

// first set the accept verdict on the packet
hdr = nfq_get_msg_packet_hdr(nfad);
nfq_set_verdict(qh,(hdr ? ntohl(hdr->packet_id) : 0),NF_ACCEPT,0,NULL);

// get the packet length and data
len = nfq_get_payload(nfad,(char **)&pkt);

// ignore packets with invalid length
if (len < (int)sizeof(struct iphdr)) return(0);

// use the iphdr structure for parsing
iphead = (iphdr *)pkt;

// ignore everything except IPv4
if (iphead->version != 4) return(0);

// we only care about TCP and UDP
if ((iphead->protocol != IPPROTO_TCP) && (iphead->protocol != IPPROTO_UDP)) return(0);

// extract the client and server addresses
saddr = ntohl(iphead->saddr);
daddr = ntohl(iphead->daddr);
inet_ntop(AF_INET,&iphead->saddr,sname,sizeof(sname));
inet_ntop(AF_INET,&iphead->daddr,dname,sizeof(dname));

	// grab TCP specific fields
	if (iphead->protocol == IPPROTO_TCP) pname = "TCP";
	{
	tcphead = (tcphdr *)&pkt[iphead->ihl << 2];
	sport = ntohs(tcphead->source);
	dport = ntohs(tcphead->dest);
	}

	// grab UDP specific fields
	if (iphead->protocol == IPPROTO_UDP) pname = "UDP";
	{
	udphead = (udphdr *)&pkt[iphead->ihl << 2];
	sport = ntohs(udphead->source);
	dport = ntohs(udphead->dest);
	}

sprintf(finder,"%s-%s:%u-%s:%u",pname,sname,sport,dname,dport);

printf("NETWORK PACKET %s\n",finder);

// pass the packet to the vineyard library
navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,pkt,len,navl_callback,NULL);

return(0);
}
/*--------------------------------------------------------------------------*/
int netfilter_startup(void)
{
char	buffer[256];
int		marker = 0;
int		ret;

/*
** The goofy marker math at the beginning of each line just gives us
** a quick and easy way to increment a return code value that will
** tell us which call failed if any of these calls return an error
*/

// spin up the vineyard engine
if ((++marker) && (navl_open(cfg_navl_flows,1,cfg_navl_plugins) != 0)) return(marker);

// enable fragment processing
if ((++marker) && (navl_ip_defrag(cfg_navl_defrag) != 0)) return(marker);

// set the TCP and UDP timeout values
if ((++marker) && (navl_conn_idle_timeout(IPPROTO_TCP,cfg_tcp_timeout) != 0)) return(marker);
if ((++marker) && (navl_conn_idle_timeout(IPPROTO_UDP,cfg_udp_timeout) != 0)) return(marker);

// grab the id values for all protocols
if ((++marker) && ((l_proto_eth = navl_proto_find_id("ETH")) < 1)) return(marker);
if ((++marker) && ((l_proto_ip = navl_proto_find_id("IP")) < 1)) return(marker);
if ((++marker) && ((l_proto_tcp = navl_proto_find_id("TCP")) < 1)) return(marker);
if ((++marker) && ((l_proto_udp = navl_proto_find_id("UDP")) < 1)) return(marker);
if ((++marker) && ((l_proto_http = navl_proto_find_id("HTTP")) < 1)) return(marker);
if ((++marker) && ((l_proto_ssl = navl_proto_find_id("SSL")) < 1)) return(marker);
if ((++marker) && ((l_proto_sip = navl_proto_find_id("SIP")) < 1)) return(marker);
if ((++marker) && ((l_proto_ctrxica = navl_proto_find_id("CTRXICA")) < 1)) return(marker);
if ((++marker) && ((l_proto_fbookapp = navl_proto_find_id("FBOOKAPP")) < 1)) return(marker);
if ((++marker) && ((l_proto_ymsgfile = navl_proto_find_id("YMSGFILE")) < 1)) return(marker);

// enable and grab the id values of the attributes we care about
if ((++marker) && ((l_attr_conn_id = navl_attr("conn.id",1)) < 1)) return(marker);
if ((++marker) && ((l_attr_ip_saddr = navl_attr("ip.src_addr",1)) < 1)) return(marker);
if ((++marker) && ((l_attr_ip_daddr = navl_attr("ip.dst_addr",1)) < 1)) return(marker);
if ((++marker) && ((l_attr_tcp_sport = navl_attr("tcp.src_port",1)) < 1)) return(marker);
if ((++marker) && ((l_attr_tcp_dport = navl_attr("tcp.dst_port",1)) < 1)) return(marker);
if ((++marker) && ((l_attr_udp_sport = navl_attr("udp.src_port",1)) < 1)) return(marker);
if ((++marker) && ((l_attr_udp_dport = navl_attr("udp.dst_port",1)) < 1)) return(marker);
if ((++marker) && ((l_attr_fbook_app = navl_attr("facebook.app",1)) < 1)) return(marker);
if ((++marker) && ((l_attr_tls_host = navl_attr("tls.host",1)) < 1)) return(marker);
if ((++marker) && ((l_attr_http_info = navl_attr("http.response.content-type",1)) < 1)) return(marker);

if ((++marker) && (navl_command("classification http persistence set","4",buffer,sizeof(buffer))) != 0) return(marker);

//open a new netfilter queue handler
nfqh = nfq_open();

	if ((++marker) && (nfqh == 0))
	{
	logmessage(LOG_ERR,"Error returned from nfq_open()\n");
	g_shutdown = 1;
	return(NULL);
	}

// unbind any existing queue handler
ret = nfq_unbind_pf(nfqh,AF_INET);

	if ((++marker) && (ret < 0))
	{
	logmessage(LOG_ERR,"Error returned from nfq_unbind_pf()\n");
	g_shutdown = 1;
	return(NULL);
	}

// bind the queue handler for AF_INET
ret = nfq_bind_pf(nfqh,AF_INET);

	if ((++marker) && (ret < 0))
	{
	logmessage(LOG_ERR,"Error returned from nfq_bind_pf(lan)\n");
	g_shutdown = 1;
	return(NULL);
	}

return(0);
}
/*--------------------------------------------------------------------------*/
void netfilter_shutdown(void)
{
// shut down the netfilter queue handler
nfq_close(nfqh);

// shut down the vineyard engine
navl_close();
}
/*--------------------------------------------------------------------------*/

