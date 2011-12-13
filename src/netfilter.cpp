// NETFILTER.CPP
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data);
int navl_callback(navl_result_t result,navl_state_t state,void *arg,int error);
int conn_callback(enum nf_conntrack_msg_type type,struct nf_conntrack *ct,void *data);
void netfilter_shutdown(void);
void vineyard_shutdown(void);
int netfilter_startup(void);
int vineyard_startup(void);
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

// call our vineyard startup function
ret = vineyard_startup();

	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from vineyard_startup()\n",ret);
	g_shutdown = 1;
	return(NULL);
	}

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

// call our vineyard shutdown function
vineyard_shutdown();

sysmessage(LOG_INFO,"The netfilter thread has terminated\n");
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

saddr.s_addr = src_addr;
daddr.s_addr = dst_addr;
strcpy(srcname,inet_ntoa(saddr));
strcpy(dstname,inet_ntoa(daddr));

	// status object is NULL and protocol is UDP so handle as new
	// session by creating the connection tracking stuff
	if ((status == NULL) && (ip_proto == IPPROTO_UDP))
	{
	ret = navl_conn_init(ntohl(src_addr),ntohs(src_port),
		ntohl(dst_addr),ntohs(dst_port),ip_proto,&dpistate);

		if (ret != 0)
		{
		sysmessage(LOG_WARNING,"Error %d returned from navl_conn_init()\n",ret);
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
	ret = navl_conn_init(ntohl(src_addr),ntohs(src_port),
		ntohl(dst_addr),ntohs(dst_port),ip_proto,&dpistate);

		if (ret != 0)
		{
		sysmessage(LOG_WARNING,"Error %d returned from navl_conn_init()\n",ret);
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
	logmessage(CAT_FILTER,LOG_DEBUG,"STATUS REMOVE = %s-%s:%u-%s:%u\n",pname,srcname,src_port,dstname,dst_port);
	g_statustable->DeleteObject(status);
	return;
	}

// don't pass zero length packets to vineyard
if (len == 0) return;

logmessage(CAT_FILTER,LOG_DEBUG,"VINEYARD (%d) = %s-%s:%u-%s:%u\n",len,pname,srcname,src_port,dstname,dst_port);

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

	// clean up terminated connections
	if (state == NAVL_STATE_TERMINATED)
	{
	logmessage(CAT_FILTER,LOG_DEBUG,"STATUS REMOVE %s\n",status->GetHashname());
	g_statustable->DeleteObject(status);
	return(0);
	}

	else
	{
	// update the status object with the new information
	status->UpdateObject(application,protochain,detail,confidence,state);
	status->GetObjectString(namestr,sizeof(namestr));
	logmessage(CAT_FILTER,LOG_DEBUG,"STATUS UPDATE %s\n",namestr);
	}

// continue tracking the flow
return(0);
}
/*--------------------------------------------------------------------------*/
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data)
{
struct nfqnl_msg_packet_hdr		*hdr;
struct nf_conntrack				*ct;
StatusObject					*status;
LookupObject					*lookup;
uint32_t						saddr,daddr;
uint16_t						sport,dport;
uint16_t						flags;
unsigned char					*rawpkt,*navpkt;
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
int								rawlen,navlen;
int								ret,off;

navpkt = NULL;
navlen = 0;
flags = 0;

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

	return(0);
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

	return(0);
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

		return(0);
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

		return(0);
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

		return(0);
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

		return(0);
		}
	}

process_traffic(flags,iphead->protocol,
	iphead->saddr,xxphead->source,
	iphead->daddr,xxphead->dest,
	navpkt,navlen,NULL);

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
int vineyard_startup(void)
{
char	buffer[1024];
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

// perpetual classification should catch on-the-fly content type changes
if ((++marker) && (navl_command("classification http persistence set","0",buffer,sizeof(buffer)) != 0)) return(marker);

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

