// CLASSIFY.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2012 Untangle, Inc.
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
MessageWagon	*wagon;
sigset_t		sigset;
time_t			current;
int				ret;

sysmessage(LOG_INFO,"The classify thread is starting\n");

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

// call our vineyard startup function
ret = vineyard_startup();

// signal the startup complete semaphore
sem_post(&g_classify_sem);

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

			// if the packet is stale we just throw it away
			if (current > (wagon->timestamp + cfg_packet_timeout)) pkt_timedrop++;

			// otherwise we send it to vineyard for classification
			else process_packet(wagon->buffer,wagon->length);

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
void process_packet(unsigned char *rawpkt,int rawlen)
{
SessionObject			*session;
TrackerObject			*tracker;
u_int32_t				saddr,daddr;
u_int16_t				sport,dport;
struct xphdr			*xphead;
struct iphdr			*iphead;
const char				*pname;
char					namestr[256];
char					sname[32];
char					dname[32];
char					forward[64];
char					reverse[64];
char					worker[64];

// use the iphdr structure for parsing
iphead = (iphdr *)rawpkt;

// setup a generic header for source and dest ports
xphead = (struct xphdr *)&rawpkt[iphead->ihl << 2];

if (iphead->protocol == IPPROTO_TCP) pname = "TCP";
if (iphead->protocol == IPPROTO_UDP) pname = "UDP";

// extract the client and server addresses
inet_ntop(AF_INET,&iphead->saddr,sname,sizeof(sname));
inet_ntop(AF_INET,&iphead->daddr,dname,sizeof(dname));
sport = ntohs(xphead->sport);
dport = ntohs(xphead->dport);

// search the hash table for the normal entry
sprintf(forward,"%s-%s:%u-%s:%u",pname,sname,sport,dname,dport);
LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION NORM FWD %s\n",forward);
session = dynamic_cast<SessionObject*>(g_sessiontable->SearchObject(forward));

	// pass the packet to the vineyard library
	if (session != NULL)
	{
	LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"FOUND NORM FWD %s\n",session->GetObjectString(namestr,sizeof(namestr)));
	if (g_debug & CAT_PACKET) log_packet(rawpkt,rawlen);
	if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,session);
	return;
	}

// not found so reverse source and destination
sprintf(reverse,"%s-%s:%u-%s:%u",pname,dname,dport,sname,sport);
LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION NORM REV %s\n",reverse);
session = dynamic_cast<SessionObject*>(g_sessiontable->SearchObject(reverse));

	// pass the packet to the vineyard library
	if (session != NULL)
	{
	LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"FOUND NORM REV %s\n",session->GetObjectString(namestr,sizeof(namestr)));
	if (g_debug & CAT_PACKET) log_packet(rawpkt,rawlen);
	if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,session);
	return;
	}

// nothing found so check the forward in the conntrack table
LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION TRAK FWD %s\n",forward);
tracker = dynamic_cast<TrackerObject*>(g_trackertable->SearchObject(forward));

	if (tracker != NULL)
	{
	// make sure we reset the timeout so active objects don't get purged
	tracker->ResetTimeout();

	LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"FOUND TRAK FWD %s\n",tracker->GetObjectString(namestr,sizeof(namestr)));
	saddr = tracker->GetSaddr();
	daddr = tracker->GetDaddr();
	inet_ntop(AF_INET,&saddr,sname,sizeof(sname));
	inet_ntop(AF_INET,&daddr,dname,sizeof(dname));
	sport = ntohs(tracker->GetSport());
	dport = ntohs(tracker->GetDport());

	sprintf(worker,"%s-%s:%u-%s:%u",pname,sname,sport,dname,dport);
	LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION TRAK FWD FWD %s\n",worker);
	session = dynamic_cast<SessionObject*>(g_sessiontable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (session != NULL)
		{
		LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"FOUND TRAK FWD FWD %s\n",tracker->GetObjectString(namestr,sizeof(namestr)));
		iphead->saddr = tracker->GetDaddr();
		xphead->sport = tracker->GetDport();
		iphead->daddr = tracker->GetSaddr();
		xphead->dport = tracker->GetSport();
		if (g_debug & CAT_PACKET) log_packet(rawpkt,rawlen);
		if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,session);
		return;
		}

	sprintf(worker,"%s-%s:%u-%s:%u",pname,dname,dport,sname,sport);
	LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION TRAK FWD REV %s\n",worker);
	session = dynamic_cast<SessionObject*>(g_sessiontable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (session != NULL)
		{
		LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"FOUND TRAK FWD REV %s\n",session->GetObjectString(namestr,sizeof(namestr)));
		iphead->saddr = tracker->GetSaddr();
		xphead->sport = tracker->GetSport();
		iphead->daddr = tracker->GetDaddr();
		xphead->dport = tracker->GetDport();
		if (g_debug & CAT_PACKET) log_packet(rawpkt,rawlen);
		if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,session);
		return;
		}
	}

// nothing found so check the reverse in the conntrack table
LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION TRAK REV %s\n",reverse);
tracker = dynamic_cast<TrackerObject*>(g_trackertable->SearchObject(reverse));

	if (tracker != NULL)
	{
	// make sure we reset the timeout so active objects don't get purged
	tracker->ResetTimeout();

	LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"FOUND TRAK REV %s\n",tracker->GetObjectString(namestr,sizeof(namestr)));
	saddr = tracker->GetSaddr();
	daddr = tracker->GetDaddr();
	inet_ntop(AF_INET,&saddr,sname,sizeof(sname));
	inet_ntop(AF_INET,&daddr,dname,sizeof(dname));
	sport = ntohs(tracker->GetSport());
	dport = ntohs(tracker->GetDport());

	sprintf(worker,"%s-%s:%u-%s:%u",pname,sname,sport,dname,dport);
	LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION TRAK REV FWD %s\n",worker);
	session = dynamic_cast<SessionObject*>(g_sessiontable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (session != NULL)
		{
		LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"FOUND TRAK REV FWD %s\n",session->GetObjectString(namestr,sizeof(namestr)));
		iphead->saddr = tracker->GetDaddr();
		xphead->sport = tracker->GetDport();
		iphead->daddr = tracker->GetSaddr();
		xphead->dport = tracker->GetSport();
		if (g_debug & CAT_PACKET) log_packet(rawpkt,rawlen);
		if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,session);
		return;
		}

	sprintf(worker,"%s-%s:%u-%s:%u",pname,dname,dport,sname,sport);
	LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION TRAK REV REV %s\n",worker);
	session = dynamic_cast<SessionObject*>(g_sessiontable->SearchObject(worker));

		// found so update the ipheader and forward to vineyard
		if (session != NULL)
		{
		LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"FOUND TRAK REV REV %s\n",session->GetObjectString(namestr,sizeof(namestr)));
		iphead->saddr = tracker->GetSaddr();
		xphead->sport = tracker->GetSport();
		iphead->daddr = tracker->GetDaddr();
		xphead->dport = tracker->GetDport();
		if (g_debug & CAT_PACKET) log_packet(rawpkt,rawlen);
		if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,session);
		return;
		}
	}

// create a new session object and store in session table
session = new SessionObject(forward,iphead->protocol,iphead->saddr,xphead->sport,iphead->daddr,xphead->dport);
g_sessiontable->InsertObject(session);
LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION INSERT %s\n",forward);

if (g_debug & CAT_PACKET) log_packet(rawpkt,rawlen);
if (g_bypass == 0) navl_conn_classify(0,0,0,0,IPPROTO_IP,NULL,rawpkt,rawlen,navl_callback,session);
}
/*--------------------------------------------------------------------------*/
void log_packet(unsigned char *rawpkt,int rawlen)
{
struct xphdr	*xphead;
struct iphdr	*iphead;
const char		*pname;
char			src_addr[32],dst_addr[32];
u_int16_t		src_port,dst_port;

// use the iphdr structure for parsing
iphead = (iphdr *)rawpkt;

// setup a generic header for source and dest ports
xphead = (struct xphdr *)&rawpkt[iphead->ihl << 2];

if (iphead->protocol == IPPROTO_TCP) pname = "TCP";
if (iphead->protocol == IPPROTO_UDP) pname = "UDP";

src_port = ntohs(xphead->sport);
dst_port = ntohs(xphead->dport);

inet_ntop(AF_INET,&iphead->saddr,src_addr,sizeof(src_addr));
inet_ntop(AF_INET,&iphead->daddr,dst_addr,sizeof(dst_addr));

LOGMESSAGE(CAT_PACKET,LOG_DEBUG,"PACKET (%d) = %s-%s:%u-%s:%u\n",rawlen,pname,src_addr,src_port,dst_addr,dst_port);
}
/*--------------------------------------------------------------------------*/
int navl_callback(navl_result_t result,navl_state_t state,void *arg,int error)
{
navl_iterator_t		it;
SessionObject		*session = (SessionObject *)arg;
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
	// but we will reset the timeout so it isn't prematurely purged
	if ((state == NAVL_STATE_CLASSIFIED) && (session->GetState() == NAVL_STATE_CLASSIFIED))
	{
	session->ResetTimeout();
	return(0);
	}

// clear local variables that we fill in while building the protochain
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

// if the session object passed is null we can't update
// this should never happen but we check just in case
if (session == NULL) return(0);

// update the session object with the new information
session->UpdateObject(application,protochain,detail,confidence,state);
LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION UPDATE %s\n",session->GetObjectString(namestr,sizeof(namestr)));

	// clean up terminated connections
	if (state == NAVL_STATE_TERMINATED)
	{
	LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION EXPIRE %s\n",session->GetHashname());
	session->ScheduleExpiration();
	}

// continue tracking the flow
return(0);
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

	if (cfg_navl_debug != 0)
	{
	// set the vineyard log level
	if ((++marker) && (navl_command("log level set","debug",buffer,sizeof(buffer)) != 0)) return(marker);
	}

// set the number of of http request+response pairs to analyze before giving up
sprintf(work,"%d",cfg_http_limit);
if ((++marker) && (navl_command("classification http persistence set",work,buffer,sizeof(buffer)) != 0)) return(marker);

// set the facebook subclassification flag
if (cfg_facebook_subclass != 0) strcpy(work,"on");
else strcpy(work,"off");
if ((++marker) && (navl_command("classification facebook subclassification set",work,buffer,sizeof(buffer)) != 0)) return(marker);

// set the skype random threshold
sprintf(work,"%d",cfg_skype_randthresh);
if ((++marker) && (navl_command("classification skype random_thresh",work,buffer,sizeof(buffer)) != 0)) return(marker);

// set the skype require history flag
sprintf(work,"%d",cfg_skype_needhist);
if ((++marker) && (navl_command("classification skype require_history",work,buffer,sizeof(buffer)) != 0)) return(marker);

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

