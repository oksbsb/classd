// CLASSIFY.CPP
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
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
void* classify_thread(void *arg)
{
MessageWagon		*wagon;
int					ret;

sysmessage(LOG_INFO,"The classify thread is starting\n");

// set the itimer value of the main thread which is required
// for gprof to work properly with multithreaded applications
setitimer(ITIMER_PROF,&g_itimer,NULL);

// call our vineyard startup function
ret = vineyard_startup();

	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from vineyard_startup()\n",ret);
	g_shutdown = 1;
	return(NULL);
	}

	while (g_shutdown == 0)
	{
	wagon = g_messagequeue->GrabMessage();
	if (wagon == NULL) continue;

		switch(wagon->command)
		{
		case MSG_SHUTDOWN:
			g_shutdown = 1;
			delete(wagon);
			break;

		case MSG_PACKET:
			process_packet(wagon->buffer,wagon->length);
			delete(wagon);
			break;
		}
	}

// call our vineyard shutdown function
vineyard_shutdown();

sysmessage(LOG_INFO,"The classify thread has terminated\n");
return(NULL);
}
/*--------------------------------------------------------------------------*/
void process_traffic(uint16_t flags,uint8_t ip_proto,
	uint32_t src_addr,
	uint16_t src_port,
	uint32_t dst_addr,
	uint16_t dst_port,
	const void *data,
	unsigned short len,
	StatusObject *status)
{
struct in_addr	saddr,daddr;
const char		*pname;
void			*dpistate;
char			hashname[64];
char			srcname[32];
char			dstname[32];
int				ret;

if (ip_proto == IPPROTO_TCP) pname = "TCP";
else if (ip_proto == IPPROTO_UDP) pname = "UDP";
else pname = "XXX";
dpistate = NULL;

saddr.s_addr = src_addr;
daddr.s_addr = dst_addr;
strcpy(srcname,inet_ntoa(saddr));
strcpy(dstname,inet_ntoa(daddr));

	// status object is NULL and protocol is UDP so handle as new
	// session by creating the connection tracking stuff
	if ((status == NULL) && (ip_proto == IPPROTO_UDP))
	{
	if (g_bypass == 0) ret = navl_conn_init(ntohl(src_addr),ntohs(src_port),ntohl(dst_addr),ntohs(dst_port),ip_proto,&dpistate);
	else ret = 0;

		if (ret != 0)
		{
		err_conninit++;
		return;
		}

	// create a new status object and store in status table
	sprintf(hashname,"%s-%s:%u-%s:%u",pname,srcname,ntohs(src_port),dstname,ntohs(dst_port));
	status = new StatusObject(hashname,ip_proto,src_addr,src_port,dst_addr,dst_port,dpistate);
	ret = g_statustable->InsertObject(status);

	logmessage(CAT_FILTER,LOG_DEBUG,"STATUS INSERT %s\n",hashname);
	}

	// status object is NULL and protocol is TCP so we
	// look at the flags and decide how to handle
	if ((status == NULL) && (ip_proto == IPPROTO_TCP))
	{
	if ((flags & TCP_SYN) == 0) return;	// must have a syn
	if ((flags & TCP_ACK) != 0) return; // ack must be clear

	// we have a clean SYN so allocate a new vineyard connection
	if (g_bypass == 0) ret = navl_conn_init(ntohl(src_addr),ntohs(src_port),ntohl(dst_addr),ntohs(dst_port),ip_proto,&dpistate);
	else ret = 0;

		if (ret != 0)
		{
		err_conninit++;
		return;
		}

	// create a new status object and store in status table
	sprintf(hashname,"%s-%s:%u-%s:%u",pname,srcname,ntohs(src_port),dstname,ntohs(dst_port));
	status = new StatusObject(hashname,ip_proto,src_addr,src_port,dst_addr,dst_port,dpistate);
	ret = g_statustable->InsertObject(status);

	logmessage(CAT_FILTER,LOG_DEBUG,"STATUS INSERT %s\n",hashname);
	}

// if arg status was empty and we didn't create a new one then we're done
if (status == NULL) return;

	// if the TCP RST flag is set figure out which side sent it
	if (flags & TCP_RST)
	{
		if ((src_addr == status->clientaddr) && (src_port == status->clientport))
		{
		logmessage(CAT_FILTER,LOG_DEBUG,"VINEYARD CLIENT RST = %s-%s:%u-%s:%u\n",pname,srcname,src_port,dstname,dst_port);
		status->clientfin = 1;
		}

		if ((src_addr == status->serveraddr) && (src_port == status->serverport))
		{
		logmessage(CAT_FILTER,LOG_DEBUG,"VINEYARD SERVER RST = %s-%s:%u-%s:%u\n",pname,srcname,src_port,dstname,dst_port);
		status->serverfin = 1;
		}
	}

	// if the TCP FIN flag is set figure out which side sent it
	if (flags & TCP_FIN)
	{
		if ((src_addr == status->clientaddr) && (src_port == status->clientport))
		{
		logmessage(CAT_FILTER,LOG_DEBUG,"VINEYARD CLIENT FIN = %s-%s:%u-%s:%u\n",pname,srcname,src_port,dstname,dst_port);
		status->clientfin = 1;
		}

		if ((src_addr == status->serveraddr) && (src_port == status->serverport))
		{
		logmessage(CAT_FILTER,LOG_DEBUG,"VINEYARD SERVER FIN = %s-%s:%u-%s:%u\n",pname,srcname,src_port,dstname,dst_port);
		status->serverfin = 1;
		}
	}

	// if the client and server fin flags are set the connection is done
	if ((status->clientfin != 0) && (status->serverfin != 0))
	{
	logmessage(CAT_FILTER,LOG_DEBUG,"STATUS EXPIRE = %s-%s:%u-%s:%u\n",pname,srcname,src_port,dstname,dst_port);
	g_statustable->ExpireObject(status);
	return;
	}

// don't pass zero length packets to vineyard
if (len == 0) return;

logmessage(CAT_FILTER,LOG_DEBUG,"VINEYARD (%d) = %s-%s:%u-%s:%u\n",len,pname,srcname,src_port,dstname,dst_port);

// if the bypass flag is set we don't pass anything to vineyard
if (g_bypass != 0) return;

navl_conn_classify(ntohl(src_addr),ntohs(src_port),ntohl(dst_addr),ntohs(dst_port),
	ip_proto,status->GetTracker(),data,len,navl_callback,status);
}
/*--------------------------------------------------------------------------*/
int navl_callback(navl_result_t result,navl_state_t state,void *arg,int error)
{
navl_iterator_t					it;
StatusObject					*status = (StatusObject *)arg;
char							application[32];
char							protochain[256];
char							namestr[256];
char							detail[256];
char							xtra[256];
char							work[32];
int								confidence,ipproto;
int								appid,value;
int								ret,idx;

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

	if (value == l_proto_tcp) ipproto = IPPROTO_TCP;
	if (value == l_proto_udp) ipproto = IPPROTO_UDP;

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

// if the status object passed is null we can't update
// this should never happen but we check just in case
if (status == NULL) return(0);

// update the status object with the new information
status->UpdateObject(application,protochain,detail,confidence,state);
status->GetObjectString(namestr,sizeof(namestr));
logmessage(CAT_FILTER,LOG_DEBUG,"STATUS UPDATE %s\n",namestr);

	// clean up terminated connections
	if (state == NAVL_STATE_TERMINATED)
	{
	logmessage(CAT_FILTER,LOG_DEBUG,"STATUS EXPIRE %s\n",status->GetHashname());
	g_statustable->ExpireObject(status);
	}

// continue tracking the flow
return(0);
}
/*--------------------------------------------------------------------------*/
void process_packet(unsigned char *rawpkt,int rawlen)
{
StatusObject					*status;
LookupObject					*lookup;
uint32_t						saddr,daddr;
uint16_t						sport,dport;
uint16_t						flags;
unsigned char					*navpkt;
struct xxphdr					*xxphead;
struct tcphdr					*tcphead;
struct udphdr					*udphead;
struct iphdr					*iphead;
const char						*pname;
char							namestr[256];
char							sname[32];
char							dname[32];
char							forward[64];
char							reverse[64];
char							worker[64];
int								navlen;
int								off;

navpkt = NULL;
navlen = 0;
flags = 0;

// use the iphdr structure for parsing
iphead = (iphdr *)rawpkt;

// setup tcp, udp, and a generic header for source and dest ports
tcphead = (struct tcphdr *)&rawpkt[iphead->ihl << 2];
udphead = (struct udphdr *)&rawpkt[iphead->ihl << 2];
xxphead = (struct xxphdr *)&rawpkt[iphead->ihl << 2];

	if (iphead->protocol == IPPROTO_TCP)
	{
	off = ((iphead->ihl << 2) + (tcphead->doff << 2));
	navpkt = &rawpkt[off];
	navlen = (rawlen - off);
	pname = "TCP";

	if (tcphead->rst) flags|=TCP_FIN;
	if (tcphead->syn) flags|=TCP_SYN;
	if (tcphead->fin) flags|=TCP_RST;
	if (tcphead->ack) flags|=TCP_ACK;
	}

	if (iphead->protocol == IPPROTO_UDP)
	{
	off = ((iphead->ihl << 2) + sizeof(struct udphdr));
	navpkt = &rawpkt[off];
	navlen = (rawlen - off);
	pname = "UDP";
	}

// extract the client and server addresses
inet_ntop(AF_INET,&iphead->saddr,sname,sizeof(sname));
inet_ntop(AF_INET,&iphead->daddr,dname,sizeof(dname));
sport = ntohs(xxphead->source);
dport = ntohs(xxphead->dest);

// search the hash table for the normal entry
sprintf(forward,"%s-%s:%u-%s:%u",pname,sname,sport,dname,dport);
logmessage(CAT_FILTER,LOG_DEBUG,"SEARCH NORM FWD %s\n",forward);
status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(forward));

	// pass the packet to the vineyard library
	if (status != NULL)
	{
	status->GetObjectString(namestr,sizeof(namestr));
	logmessage(CAT_FILTER,LOG_DEBUG,"FOUND NORM FWD %s\n",namestr);

	process_traffic(flags,iphead->protocol,
		iphead->saddr,xxphead->source,
		iphead->daddr,xxphead->dest,
		navpkt,navlen,status);

	return;
	}

// not found so reverse source and destination
sprintf(reverse,"%s-%s:%u-%s:%u",pname,dname,dport,sname,sport);
logmessage(CAT_FILTER,LOG_DEBUG,"SEARCH NORM REV %s\n",reverse);
status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(reverse));

	// pass the packet to the vineyard library
	if (status != NULL)
	{
	status->GetObjectString(namestr,sizeof(namestr));
	logmessage(CAT_FILTER,LOG_DEBUG,"FOUND NORM REV %s\n",namestr);

	process_traffic(flags,iphead->protocol,
		iphead->saddr,xxphead->source,
		iphead->daddr,xxphead->dest,
		navpkt,navlen,status);

	return;
	}

// nothing found so check the forward in the conntrack table
logmessage(CAT_FILTER,LOG_DEBUG,"SEARCH LOOK FWD %s\n",forward);
lookup = dynamic_cast<LookupObject*>(g_lookuptable->SearchObject(forward));

	if (lookup != NULL)
	{
	lookup->GetObjectString(namestr,sizeof(namestr));
	logmessage(CAT_FILTER,LOG_DEBUG,"FOUND LOOK FWD %s\n",namestr);
	saddr = lookup->GetSaddr();
	daddr = lookup->GetDaddr();
	inet_ntop(AF_INET,&saddr,sname,sizeof(sname));
	inet_ntop(AF_INET,&daddr,dname,sizeof(dname));
	sport = ntohs(lookup->GetSport());
	dport = ntohs(lookup->GetDport());

	sprintf(worker,"%s-%s:%u-%s:%u",pname,sname,sport,dname,dport);
	logmessage(CAT_FILTER,LOG_DEBUG,"SEARCH CONN FWD FWD %s\n",worker);
	status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (status != NULL)
		{
		status->GetObjectString(namestr,sizeof(namestr));
		logmessage(CAT_FILTER,LOG_DEBUG,"FOUND CONN FWD FWD %s\n",namestr);

		process_traffic(flags,iphead->protocol,
			lookup->GetDaddr(),lookup->GetDport(),
			lookup->GetSaddr(),lookup->GetSport(),
			navpkt,navlen,status);

		return;
		}

	sprintf(worker,"%s-%s:%u-%s:%u",pname,dname,dport,sname,sport);
	logmessage(CAT_FILTER,LOG_DEBUG,"SEARCH CONN FWD REV %s\n",worker);
	status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (status != NULL)
		{
		status->GetObjectString(namestr,sizeof(namestr));
		logmessage(CAT_FILTER,LOG_DEBUG,"FOUND CONN FWD REV %s\n",namestr);

		process_traffic(flags,iphead->protocol,
			lookup->GetSaddr(),lookup->GetSport(),
			lookup->GetDaddr(),lookup->GetDport(),
			navpkt,navlen,status);

		return;
		}
	}

// nothing found so check the reverse in the conntrack table
logmessage(CAT_FILTER,LOG_DEBUG,"SEARCH LOOK REV %s\n",reverse);
lookup = dynamic_cast<LookupObject*>(g_lookuptable->SearchObject(reverse));

	if (lookup != NULL)
	{
	lookup->GetObjectString(namestr,sizeof(namestr));
	logmessage(CAT_FILTER,LOG_DEBUG,"FOUND LOOK REV %s\n",namestr);
	saddr = lookup->GetSaddr();
	daddr = lookup->GetDaddr();
	inet_ntop(AF_INET,&saddr,sname,sizeof(sname));
	inet_ntop(AF_INET,&daddr,dname,sizeof(dname));
	sport = ntohs(lookup->GetSport());
	dport = ntohs(lookup->GetDport());

	sprintf(worker,"%s-%s:%u-%s:%u",pname,sname,sport,dname,dport);
	logmessage(CAT_FILTER,LOG_DEBUG,"SEARCH CONN REV FWD %s\n",worker);
	status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (status != NULL)
		{
		status->GetObjectString(namestr,sizeof(namestr));
		logmessage(CAT_FILTER,LOG_DEBUG,"FOUND CONN REV FWD %s\n",namestr);

		process_traffic(flags,iphead->protocol,
			lookup->GetDaddr(),lookup->GetDport(),
			lookup->GetSaddr(),lookup->GetSport(),
			navpkt,navlen,status);

		return;
		}

	sprintf(worker,"%s-%s:%u-%s:%u",pname,dname,dport,sname,sport);
	logmessage(CAT_FILTER,LOG_DEBUG,"SEARCH CONN REV REV %s\n",worker);
	status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (status != NULL)
		{
		status->GetObjectString(namestr,sizeof(namestr));
		logmessage(CAT_FILTER,LOG_DEBUG,"FOUND CONN REV REV %s\n",namestr);

		process_traffic(flags,iphead->protocol,
			lookup->GetSaddr(),lookup->GetSport(),
			lookup->GetDaddr(),lookup->GetDport(),
			navpkt,navlen,status);

		return;
		}
	}

process_traffic(flags,iphead->protocol,
	iphead->saddr,xxphead->source,
	iphead->daddr,xxphead->dest,
	navpkt,navlen,NULL);

return;
}
/*--------------------------------------------------------------------------*/
int vineyard_startup(void)
{
char	buffer[1024];
char	work[32];
int		marker = 0;

/*
** The goofy marker math at the beginning of each line just gives us
** a quick and easy way to increment a return code value that will
** tell us which call failed if any of these calls return an error
*/

// spin up the vineyard engine
if ((++marker) && (navl_open(cfg_navl_flows,1,cfg_navl_plugins) != 0)) return(marker);

// set the vineyard log level
if ((++marker) && (navl_command("log level set","debug",buffer,sizeof(buffer)) != 0)) return(marker);

// set the number of of http request+response pairs to analyze before giving up
sprintf(work,"%d",cfg_http_limit);
if ((++marker) && (navl_command("classification http persistence set",work,buffer,sizeof(buffer)) != 0)) return(marker);

// disable all connection management in vineyard
if ((++marker) && (navl_conn_idle_timeout(IPPROTO_TCP,0) != 0)) return(marker);
if ((++marker) && (navl_conn_idle_timeout(IPPROTO_UDP,0) != 0)) return(marker);

// enable fragment processing
if ((++marker) && (navl_ip_defrag(cfg_navl_defrag) != 0)) return(marker);

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

return(0);
}
/*--------------------------------------------------------------------------*/
void vineyard_shutdown(void)
{
// shut down the vineyard engine
navl_close();
}
/*--------------------------------------------------------------------------*/

