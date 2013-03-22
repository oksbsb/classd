// CLASSIFY.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2013 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
// vars for the protocol and application id values we want
static int l_proto_tcp = 0;
static int l_proto_udp = 0;

// local variables
static navl_handle_t l_navl_handle = NULL;
static int l_navl_logfile = 0;
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

	// if there were any vineyard startup errors set the shutdown flag
	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from vineyard_startup()\n",ret);
	g_shutdown = 1;
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

		case MSG_DEBUG:
			vineyard_debug((char *)wagon->buffer);
			delete(wagon);
			break;

		default:
			sysmessage(LOG_WARNING,"Unknown thread message received = %c\n",wagon->command);
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
	if (g_bypass == 0) navl_classify(l_navl_handle,NAVL_ENCAP_IP,rawpkt,rawlen,NULL,0,navl_callback,session);
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
	if (g_bypass == 0) navl_classify(l_navl_handle,NAVL_ENCAP_IP,rawpkt,rawlen,NULL,0,navl_callback,session);
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
		if (g_bypass == 0) navl_classify(l_navl_handle,NAVL_ENCAP_IP,rawpkt,rawlen,NULL,0,navl_callback,session);
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
		if (g_bypass == 0) navl_classify(l_navl_handle,NAVL_ENCAP_IP,rawpkt,rawlen,NULL,0,navl_callback,session);
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
		if (g_bypass == 0) navl_classify(l_navl_handle,NAVL_ENCAP_IP,rawpkt,rawlen,NULL,0,navl_callback,session);
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
		if (g_bypass == 0) navl_classify(l_navl_handle,NAVL_ENCAP_IP,rawpkt,rawlen,NULL,0,navl_callback,session);
		return;
		}
	}

// create a new session object and store in session table
session = new SessionObject(forward,iphead->protocol,iphead->saddr,xphead->sport,iphead->daddr,xphead->dport);
g_sessiontable->InsertObject(session);
LOGMESSAGE(CAT_UPDATE,LOG_DEBUG,"CLASSIFY INSERT %s\n",forward);

if (g_debug & CAT_PACKET) log_packet(rawpkt,rawlen);
if (g_bypass == 0) navl_classify(l_navl_handle,NAVL_ENCAP_IP,rawpkt,rawlen,NULL,0,navl_callback,session);
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
int navl_callback(navl_handle_t handle,navl_result_t result,navl_state_t state,navl_conn_t conn,void *arg,int error)
{
navl_iterator_t		it;
SessionObject		*session = (SessionObject *)arg;
const char			*check;
char				application[32];
char				protochain[256];
char				namestr[256];
char				work[32];
int					confidence,ipproto;
int					appid,value;
int					idx;

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
appid = navl_app_get(handle,result,&confidence);
navl_proto_get_name(handle,appid,application,sizeof(application));

	// build the protochain grabbing extra info for certain protocols
	for(it = navl_proto_first(handle,result);navl_proto_valid(handle,it);navl_proto_next(handle,it))
	{
	value = navl_proto_get_index(handle,it);

	if (value == l_proto_tcp) ipproto = IPPROTO_TCP;
	if (value == l_proto_udp) ipproto = IPPROTO_UDP;

	// append the protocol name to the chain
	work[0] = 0;
	check = navl_proto_get_name(handle,value,work,sizeof(work));
	if (check == NULL) break;
	idx+=snprintf(&protochain[idx],sizeof(protochain),"/%s",work);
	}

// only TCP or UDP packets will set this flag allowing
// us to ignore all other unknown protocol values
if (ipproto == 0) return(0);

// if the session object passed is null we can't update
// this should never happen but we check just in case
if (session == NULL) return(0);

// update the session object with the new information
session->UpdateObject(application,protochain,confidence,state);
LOGMESSAGE(CAT_UPDATE,LOG_DEBUG,"CLASSIFY UPDATE %s\n",session->GetObjectString(namestr,sizeof(namestr)));

	// clean up terminated connections
	if (state == NAVL_STATE_TERMINATED)
	{
	LOGMESSAGE(CAT_UPDATE,LOG_DEBUG,"CLASSIFY EXPIRE %s\n",session->GetHashname());
	session->ScheduleExpiration();
	}

// continue tracking the flow
return(0);
}
/*--------------------------------------------------------------------------*/
void attr_callback(navl_handle_t handle,navl_conn_t conn,int attr_type,int attr_length,const void *attr_value,int attr_flag,void *arg)
{
SessionObject		*session = (SessionObject *)arg;
char				namestr[256];
char				detail[256];

// if the session object passed is null we can't update
// this should never happen but we check just in case
if (session == NULL) return;

	// check for the facebook application name
	// FIXME - do the key lookup once during init when vineyard fixes their shit
	if (attr_type == navl_attr_key_get(handle,"facebook.app"))
	{
	memcpy(detail,attr_value,attr_length);
	detail[attr_length] = 0;
	}

	// check for the tls host name
	// FIXME - do the key lookup once during init when vineyard fixes their shit
	else if (attr_type == navl_attr_key_get(l_navl_handle,"tls.host"))
	{
	memcpy(detail,attr_value,attr_length);
	detail[attr_length] = 0;
	}

	// nothing we signed up for so just ignore and return
	else
	{
	return;
	}

// update the session object with the data received
LOGMESSAGE(CAT_UPDATE,LOG_DEBUG,"CLASSIFY DETAIL %s\n",session->GetObjectString(namestr,sizeof(namestr)));
session->UpdateDetail(detail);
}
/*--------------------------------------------------------------------------*/
int vineyard_startup(void)
{
char	temp[32],work[32];
int		problem = 0;
int		ret,x;

// bind the vineyard external references
navl_bind_externals();

// spin up the vineyard engine
l_navl_handle = navl_open(cfg_navl_plugins);

	if (l_navl_handle == -1)
	{
	ret = navl_error_get(0);
	sysmessage(LOG_ERR,"Error %d returned from navl_open()\n",ret);
	return(1);
	}

// set the vineyard system loglevel parameter
if (vineyard_config("system.loglevel",cfg_navl_debug) != 0) return(1);

// set the number of of http request+response pairs to analyze before giving up
if (vineyard_config("http.maxpersist",cfg_http_limit) != 0) return(1);

// set the TCP session timeout
if (vineyard_config("tcp.timeout",cfg_tcp_timeout) != 0) return(1);

// set the UDP session timeout
if (vineyard_config("udp.timeout",cfg_udp_timeout) != 0) return(1);

// enable IP fragment processing
if (vineyard_config("ip.defrag",cfg_navl_defrag) != 0) return(1);

// set all the low level skype parameters
if (vineyard_config("skype.probe_thresh",cfg_skype_probe_thresh) != 0) return(1);
if (vineyard_config("skype.packet_thresh",cfg_skype_packet_thresh) != 0) return(1);
if (vineyard_config("skype.random_thresh",cfg_skype_random_thresh) != 0) return(1);
if (vineyard_config("skype.require_history",cfg_skype_require_history) != 0) return(1);

// initialize the vineyard handle for the active thread
ret = navl_init(l_navl_handle);

	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from navl_init()\n",ret);
	return(1);
	}

// grab the index values for protocols we care about
if ((l_proto_tcp = navl_proto_find_index(l_navl_handle,"TCP")) == -1) problem|=0x01;
if ((l_proto_udp = navl_proto_find_index(l_navl_handle,"UDP")) == -1) problem|=0x02;

	if (problem != 0)
	{
	sysmessage(LOG_ERR,"Error 0x%02X collecting protocol indexes\n",problem);
	return(1);
	}

if ((navl_attr_callback_set(l_navl_handle,"facebook.app",attr_callback) == -1)) problem|=0x01;
if ((navl_attr_callback_set(l_navl_handle,"tls.host",attr_callback) == -1)) problem|=0x02;

	if (problem != 0)
	{
	sysmessage(LOG_ERR,"Error 0x%02X enabling metadata callbacks\n");
	return(1);
	}

// get the total number of protocols from the vineyard library
ret = navl_proto_max_index(l_navl_handle);

	if (ret == -1)
	{
	sysmessage(LOG_ERR,"Error calling navl_proto_max_index()\n");
	return(1);
	}

// allocate a chunk of memory and store the protocol list
g_protolist = (char *)malloc(ret * 16);
g_protolist[0] = 0;

	// get the name of each protocol and append to buffer
	for(x = 0;x < ret;x++)
	{
	work[0] = 0;
	navl_proto_get_name(l_navl_handle,x,work,sizeof(work));
	if (strlen(work) == 0) continue;
	sprintf(temp,"%d = %s\r\n",x,work);
	strcat(g_protolist,temp);
	}

return(0);
}
/*--------------------------------------------------------------------------*/
int vineyard_config(const char *key,int value)
{
char		work[32];
int			ret;

sprintf(work,"%d",value);
ret = navl_config_set(l_navl_handle,key,work);
if (ret != 0) sysmessage(LOG_ERR,"Error calling navl_config_set(%s)\n",key);
return(ret);
}
/*--------------------------------------------------------------------------*/
void vineyard_shutdown(void)
{
// finalize the vineyard library
navl_fini(l_navl_handle);

// shut down the vineyard engine
navl_close(l_navl_handle);
}
/*--------------------------------------------------------------------------*/
void vineyard_debug(const char *dumpfile)
{
FILE		*stream;

// open the dumpfile for append
stream = fopen(dumpfile,"a");

// set file descriptor to capture output from vineyard
l_navl_logfile = fileno(stream);

// dump the vineyard diagnostic info and include calls
// to fflush since we're passing the file descriptor

fprintf(stream,"========== VINEYARD CONFIG INFO ==========\r\n");
fflush(stream);
navl_config_dump(l_navl_handle);

fprintf(stream,"========== VINEYARD SYSTEM INFO ==========\r\n");
fflush(stream);
navl_diag(l_navl_handle,"SYSTEM","");

fprintf(stream,"========== VINEYARD TCP INFO ==========\r\n");
fflush(stream);
navl_diag(l_navl_handle,"TCP","");

fprintf(stream,"========== VINEYARD UDP INFO ==========\r\n");
fflush(stream);
navl_diag(l_navl_handle,"UDP","");

// clear the file descriptor before we close the file
l_navl_logfile = 0;

fprintf(stream,"\r\n");
fclose(stream);
}
/*--------------------------------------------------------------------------*/
int	vineyard_logger(const char *level,const char *func,const char *format,...)
{
va_list		args;
char		header[256];
char		buffer[4096];
int			len;

sprintf(header,"VINEYARD %s %s",level,func);

va_start(args,format);
len = vsnprintf(buffer,sizeof(buffer),format,args);
va_end(args);

sysmessage(LOG_NOTICE,"%s --> %s\n",header,buffer);

return(len);
}
/*--------------------------------------------------------------------------*/
int vineyard_printf(const char *format,...)
{
va_list		args;
char		buffer[4096];
int			len;

// if the file descriptor is clear just ignore
if (l_navl_logfile == 0) return(0);

va_start(args,format);
len = vsnprintf(buffer,sizeof(buffer),format,args);
va_end(args);

write(l_navl_logfile,buffer,len);

return(len);
}
/*--------------------------------------------------------------------------*/

