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

// vars for the conntrack lookups
struct nfct_handle *nfcth;
/*--------------------------------------------------------------------------*/
void* classify_thread(void *arg)
{
MessageWagon	*wagon;
time_t			current;
int				ret;

sysmessage(LOG_INFO,"The classify thread is starting\n");

// set the itimer value of the main thread which is required
// for gprof to work properly with multithreaded applications
setitimer(ITIMER_PROF,&g_itimer,NULL);

// open a conntrack netlink handler
nfcth = nfct_open(CONNTRACK,NFNL_SUBSYS_CTNETLINK);

	if (nfcth == NULL)
	{
	sysmessage(LOG_ERR,"Error %d returned from nfct_open()\n",errno);
	g_shutdown = 1;
	return(NULL);
	}

// register the conntrack callback
ret = nfct_callback_register(nfcth,NFCT_T_ALL,conn_callback,NULL);

	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from nfct_callback_register()\n",errno);
	g_shutdown = 1;
	return(NULL);
	}

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
			current = time(NULL);
			if (current > (wagon->timestamp + cfg_packet_timeout)) pkt_timedrop++;
			else process_packet(wagon->buffer,wagon->length);
			delete(wagon);
			break;
		}
	}

// call our vineyard shutdown function
vineyard_shutdown();

// unregister the callback handler
nfct_callback_unregister(nfcth);

// close the conntrack netlink handler
nfct_close(nfcth);

sysmessage(LOG_INFO,"The classify thread has terminated\n");
return(NULL);
}
/*--------------------------------------------------------------------------*/
void process_packet(unsigned char *rawpkt,int rawlen)
{
struct nf_conntrack		*ct;
StatusObject			*status;
LookupObject			*lookup;
uint32_t				saddr,daddr;
uint16_t				sport,dport;
struct xphdr			*xphead;
struct iphdr			*iphead;
const char				*pname;
char					namestr[256];
char					sname[32];
char					dname[32];
char					forward[64];
char					reverse[64];
char					worker[64];
int						ret;

// use the iphdr structure for parsing
iphead = (iphdr *)rawpkt;

// setup a generic header for source and dest ports
xphead = (struct xphdr *)&rawpkt[iphead->ihl << 2];

if (iphead->protocol == IPPROTO_TCP) pname = "TCP";
if (iphead->protocol == IPPROTO_UDP) pname = "UDP";

// allocate a new conntrack
ct = nfct_new();

	// on error increment the fail counter
	if (ct == NULL)
	{
	pkt_faildrop++;
	return;
	}

// setup and submit the conntrack query
nfct_set_attr_u8(ct,ATTR_L3PROTO,AF_INET);
nfct_set_attr_u8(ct,ATTR_L4PROTO,iphead->protocol);
nfct_set_attr_u32(ct,ATTR_IPV4_SRC,iphead->saddr);
nfct_set_attr_u16(ct,ATTR_PORT_SRC,xphead->source);
nfct_set_attr_u32(ct,ATTR_IPV4_DST,iphead->daddr);
nfct_set_attr_u16(ct,ATTR_PORT_DST,xphead->dest);
ret = nfct_query(nfcth,NFCT_Q_GET,ct);

// cleanup the conntrack
nfct_destroy(ct);

// extract the client and server addresses
inet_ntop(AF_INET,&iphead->saddr,sname,sizeof(sname));
inet_ntop(AF_INET,&iphead->daddr,dname,sizeof(dname));
sport = ntohs(xphead->source);
dport = ntohs(xphead->dest);

// search the hash table for the normal entry
sprintf(forward,"%s-%s:%u-%s:%u",pname,sname,sport,dname,dport);
LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"SEARCH NORM FWD %s\n",forward);
status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(forward));

	// pass the packet to the vineyard library
	if (status != NULL)
	{
	LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"FOUND NORM FWD %s\n",status->GetObjectString(namestr,sizeof(namestr)));
	log_packet(rawpkt,rawlen);
	if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,status);
	return;
	}

// not found so reverse source and destination
sprintf(reverse,"%s-%s:%u-%s:%u",pname,dname,dport,sname,sport);
LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"SEARCH NORM REV %s\n",reverse);
status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(reverse));

	// pass the packet to the vineyard library
	if (status != NULL)
	{
	LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"FOUND NORM REV %s\n",status->GetObjectString(namestr,sizeof(namestr)));
	log_packet(rawpkt,rawlen);
	if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,status);
	return;
	}

// nothing found so check the forward in the conntrack table
LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"SEARCH LOOK FWD %s\n",forward);
lookup = dynamic_cast<LookupObject*>(g_lookuptable->SearchObject(forward));

	if (lookup != NULL)
	{
	LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"FOUND LOOK FWD %s\n",lookup->GetObjectString(namestr,sizeof(namestr)));
	saddr = lookup->GetSaddr();
	daddr = lookup->GetDaddr();
	inet_ntop(AF_INET,&saddr,sname,sizeof(sname));
	inet_ntop(AF_INET,&daddr,dname,sizeof(dname));
	sport = ntohs(lookup->GetSport());
	dport = ntohs(lookup->GetDport());

	sprintf(worker,"%s-%s:%u-%s:%u",pname,sname,sport,dname,dport);
	LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"SEARCH CONN FWD FWD %s\n",worker);
	status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (status != NULL)
		{
		LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"FOUND CONN FWD FWD %s\n",lookup->GetObjectString(namestr,sizeof(namestr)));
		iphead->saddr = lookup->GetDaddr();
		xphead->source = lookup->GetDport();
		iphead->daddr = lookup->GetSaddr();
		xphead->dest = lookup->GetSport();
		log_packet(rawpkt,rawlen);
		if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,status);
		return;
		}

	sprintf(worker,"%s-%s:%u-%s:%u",pname,dname,dport,sname,sport);
	LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"SEARCH CONN FWD REV %s\n",worker);
	status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (status != NULL)
		{
		LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"FOUND CONN FWD REV %s\n",status->GetObjectString(namestr,sizeof(namestr)));
		iphead->saddr = lookup->GetSaddr();
		xphead->source = lookup->GetSport();
		iphead->daddr = lookup->GetDaddr();
		xphead->dest = lookup->GetDport();
		log_packet(rawpkt,rawlen);
		if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,status);
		return;
		}
	}

// nothing found so check the reverse in the conntrack table
LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"SEARCH LOOK REV %s\n",reverse);
lookup = dynamic_cast<LookupObject*>(g_lookuptable->SearchObject(reverse));

	if (lookup != NULL)
	{
	LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"FOUND LOOK REV %s\n",lookup->GetObjectString(namestr,sizeof(namestr)));
	saddr = lookup->GetSaddr();
	daddr = lookup->GetDaddr();
	inet_ntop(AF_INET,&saddr,sname,sizeof(sname));
	inet_ntop(AF_INET,&daddr,dname,sizeof(dname));
	sport = ntohs(lookup->GetSport());
	dport = ntohs(lookup->GetDport());

	sprintf(worker,"%s-%s:%u-%s:%u",pname,sname,sport,dname,dport);
	LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"SEARCH CONN REV FWD %s\n",worker);
	status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (status != NULL)
		{
		LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"FOUND CONN REV FWD %s\n",status->GetObjectString(namestr,sizeof(namestr)));
		iphead->saddr = lookup->GetDaddr();
		xphead->source = lookup->GetDport();
		iphead->daddr = lookup->GetSaddr();
		xphead->dest = lookup->GetSport();
		log_packet(rawpkt,rawlen);
		if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,status);
		return;
		}

	sprintf(worker,"%s-%s:%u-%s:%u",pname,dname,dport,sname,sport);
	LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"SEARCH CONN REV REV %s\n",worker);
	status = dynamic_cast<StatusObject*>(g_statustable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (status != NULL)
		{
		LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"FOUND CONN REV REV %s\n",status->GetObjectString(namestr,sizeof(namestr)));
		iphead->saddr = lookup->GetSaddr();
		xphead->source = lookup->GetSport();
		iphead->daddr = lookup->GetDaddr();
		xphead->dest = lookup->GetDport();
		log_packet(rawpkt,rawlen);
		if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,status);
		return;
		}
	}

// create a new status object and store in status table
status = new StatusObject(forward,iphead->protocol,iphead->saddr,xphead->source,iphead->daddr,xphead->dest);
g_statustable->InsertObject(status);
LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"STATUS INSERT %s\n",forward);

log_packet(rawpkt,rawlen);
if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,status);
}
/*--------------------------------------------------------------------------*/
void log_packet(unsigned char *rawpkt,int rawlen)
{
struct xphdr	*xphead;
struct iphdr	*iphead;
const char		*pname;
char			src_addr[32],dst_addr[32];
uint16_t		src_port,dst_port;

// use the iphdr structure for parsing
iphead = (iphdr *)rawpkt;

// setup a generic header for source and dest ports
xphead = (struct xphdr *)&rawpkt[iphead->ihl << 2];

if (iphead->protocol == IPPROTO_TCP) pname = "TCP";
if (iphead->protocol == IPPROTO_UDP) pname = "UDP";

src_port = ntohs(xphead->source);
dst_port = ntohs(xphead->dest);

inet_ntop(AF_INET,&iphead->saddr,src_addr,sizeof(src_addr));
inet_ntop(AF_INET,&iphead->daddr,dst_addr,sizeof(dst_addr));

LOGMESSAGE(CAT_PACKET,LOG_DEBUG,"PACKET (%d) = %s-%s:%u-%s:%u\n",rawlen,pname,src_addr,src_port,dst_addr,dst_port);
}
/*--------------------------------------------------------------------------*/
int navl_callback(navl_result_t result,navl_state_t state,void *arg,int error)
{
navl_iterator_t		it;
StatusObject		*status = (StatusObject *)arg;
char				application[32];
char				protochain[256];
char				namestr[256];
char				detail[256];
char				xtra[256];
char				work[32];
int					confidence,ipproto;
int					appid,value;
int					ret,idx;

// if callback and object state are both classified no need to process
if ((state == NAVL_STATE_CLASSIFIED) && (status->GetState() == NAVL_STATE_CLASSIFIED)) return(0);

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
LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"STATUS UPDATE %s\n",status->GetObjectString(namestr,sizeof(namestr)));

	// clean up terminated connections
	if (state == NAVL_STATE_TERMINATED)
	{
	LOGMESSAGE(CAT_LOOKUP,LOG_DEBUG,"STATUS EXPIRE %s\n",status->GetHashname());
	g_statustable->ExpireObject(status);
	}

// continue tracking the flow
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

LOGMESSAGE(CAT_FILTER,LOG_DEBUG,"TRACKER SEARCH %s\n",finder);
lookup = dynamic_cast<LookupObject*>(g_lookuptable->SearchObject(finder));

	if (lookup == NULL)
	{
	lookup = new LookupObject(orig_proto,finder);
	lookup->UpdateObject(orig_saddr,orig_sport,orig_daddr,orig_dport);
	LOGMESSAGE(CAT_FILTER,LOG_DEBUG,"TRACKER INSERT %s\n",lookup->GetObjectString(namestr,sizeof(namestr)));
	g_lookuptable->InsertObject(lookup);
	}

	else
	{
	lookup->UpdateObject(orig_saddr,orig_sport,orig_daddr,orig_dport);
	LOGMESSAGE(CAT_FILTER,LOG_DEBUG,"TRACKER UPDATE %s\n",lookup->GetObjectString(namestr,sizeof(namestr)));
	}

return(NFCT_CB_CONTINUE);
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

// set the protocol idle timeout values
if ((++marker) && (navl_conn_idle_timeout(IPPROTO_TCP,cfg_tcp_timeout) != 0)) return(marker);
if ((++marker) && (navl_conn_idle_timeout(IPPROTO_UDP,cfg_udp_timeout) != 0)) return(marker);

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

