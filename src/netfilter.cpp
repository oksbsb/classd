// NETFILTER.C
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *tb,void *arg);
int navl_callback(navl_result_t result,navl_state_t state,void *arg,int error);
void qclassify_exit(void);
void qclassify_loop(void);
int qclassify_init(void);
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
/*--------------------------------------------------------------------------*/
void* netfilter_thread(void *arg)
{
int		ret;

logmessage(LOG_INFO,"The netfilter thread is starting\n");

// set the itimer value of the main thread which is required
// for gprof to work properly with multithreaded applications
setitimer(ITIMER_PROF,&g_itimer,NULL);

ret = qclassify_init();

	if (ret != 0)
	{
	logmessage(LOG_ERR,"Error %d returned from qclassify_init()\n",ret);
	qclassify_exit();
	g_shutdown = 1;
	return(NULL);
	}

qclassify_loop();
qclassify_exit();

logmessage(LOG_INFO,"The netfilter thread has terminated\n");
return(NULL);
}
/*--------------------------------------------------------------------------*/
int qclassify_init(void)
{
char	buffer[256];
int		marker = 0;

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

if ((++marker) && (navl_command("classification http persistence set","0",buffer,sizeof(buffer))) != 0) return(marker);

return(0);
}
/*--------------------------------------------------------------------------*/
void qclassify_exit()
{
// shut down the vineyard engine
navl_close();
}
/*--------------------------------------------------------------------------*/
void qclassify_loop()
{
struct nfq_q_handle		*qh;
struct nfq_handle		*nfqh;
struct pollfd			pollinfo;
char					buffer[2048];
int						fd,ret;

//open a new netqueue handler
nfqh = nfq_open();

	if (nfqh == 0)
	{
	logmessage(LOG_ERR,"Error returned from nfq_open()\n");
	g_shutdown = 1;
	return;
	}

// unbind any existing queue handler
ret = nfq_unbind_pf(nfqh,AF_INET);

	if (ret < 0)
	{
	logmessage(LOG_ERR,"Error returned from nfq_unbind_pf()\n");
	g_shutdown = 1;
	return;
	}

// bind the queue handler for AF_INET
ret = nfq_bind_pf(nfqh,AF_INET);

	if (ret < 0)
	{
	logmessage(LOG_ERR,"Error returned from nfq_bind_pf()\n");
	g_shutdown = 1;
	return;
	}

// create a new queue handler
qh = nfq_create_queue(nfqh,cfg_net_queue,&netq_callback,NULL);

	if (qh == 0)
	{
	logmessage(LOG_ERR,"Error returned from nfq_create_queue(%u)\n",cfg_net_queue);
	g_shutdown = 1;
	return;
	}

// set the queue data copy mode
ret = nfq_set_mode(qh,NFQNL_COPY_PACKET,0xFFFF);

	if (ret < 0)
	{
	logmessage(LOG_ERR,"failed to set NFQNL_COPY_PACKET\n");
	g_shutdown = 1;
	return;
	}

// get the file descriptor for netlink queue
fd = nfnl_fd(nfq_nfnlh(nfqh));

	while (g_shutdown == 0)
	{
	pollinfo.fd = fd;
	pollinfo.events = POLLIN;

	// wait for data
	ret = poll(&pollinfo,1,1000);

		if ((ret < 0) && (errno != EINTR))
		{
		logmessage(LOG_ERR,"poll error nfq fd %d (%d/%s)\n",fd,errno,strerror(errno));
		break;
		}

	// process the data
	while ((ret = recv(fd,buffer,sizeof(buffer),MSG_DONTWAIT)) > 0) nfq_handle_packet(nfqh,buffer,ret);

		if (ret == -1)
		{
		if (errno == EAGAIN || errno == EINTR || errno == ENOBUFS) continue;
		logmessage(LOG_ERR,"recv error nfq fd %d (%d/%s)\n",fd,errno,strerror(errno));
		break;
		}

		else if (ret == 0)
		{
		logmessage(LOG_ERR,"nfq socket closed\n");
		break;
		}
	}
}
/*--------------------------------------------------------------------------*/
int navl_callback(navl_result_t result,navl_state_t state,void *arg,int error)
{
struct nfqnl_msg_packet_hdr		*hdr;
struct callback_info			*ci;
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
char							source[32];
char							target[32];
char							xtra[256];
char							work[32];

application[0] = 0;
protochain[0] = 0;
detail[0] = 0;
confidence = 0;
ipproto = 0;
idx = 0;

// first set the accept verdict on the packet
ci = (struct callback_info *)arg;
hdr = nfq_get_msg_packet_hdr(ci->data);
nfq_set_verdict(ci->handle,(hdr ? ntohl(hdr->packet_id) : 0),NF_ACCEPT,0,NULL);

	// keep track of errors returned by vineyard
	if (error != 0) switch (error)
	{
	case ENOMEM:	err_nomem++;	return(1);
	case ENOBUFS:	err_nobufs++;	return(1);
	case ENOSR:		err_nosr++;		return(1);
	case ENOTCONN:	err_notconn++;	return(1);
	default:		err_unknown++;	return(1);
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
strcpy(source,inet_ntoa(saddr));
strcpy(target,inet_ntoa(daddr));

if (ipproto == IPPROTO_TCP) sprintf(finder,"TCP-%s:%d-%s:%d",source,sport,target,dport);
if (ipproto == IPPROTO_UDP) sprintf(finder,"UDP-%s:%d-%s:%d",source,sport,target,dport);

// search the hash table for the entry
local = g_conntable->SearchObject(finder);

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

// increment counter and continue tracking the flow
return(0);
}
/*--------------------------------------------------------------------------*/
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *tb,void *arg)
{
struct callback_info	ci;
char					*data;
int						datalen;

// get the packet length
datalen = nfq_get_payload(tb,&data);

	// pass valid packets to the vineyard library
	if (datalen > 0)
	{
	ci.handle = qh;
	ci.data = tb;
	navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,data,datalen,navl_callback,&ci);
	}

return(0);
}
/*--------------------------------------------------------------------------*/

