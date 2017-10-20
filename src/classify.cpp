// CLASSIFY.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2013 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"

#define CLIENT_to_SERVER	0
#define SERVER_to_CLIENT	1
#define INVALID_VALUE		1234567890

/*--------------------------------------------------------------------------*/
// local variables
static navl_handle_t l_navl_handle = (navl_handle_t)NULL;
static int l_navl_logfile = 0;

// vars for the attribute names we track
static const char *l_name_facebook_app = "facebook.app";
static const char *l_name_tls_hostname = "tls.hostname";

// vars to hold the detail attributes we track
int l_attr_facebook_app = INVALID_VALUE;
int l_attr_tls_hostname = INVALID_VALUE;
/*--------------------------------------------------------------------------*/
void* classify_thread(void *arg)
{
MessageWagon	*wagon;
SessionObject	*session;
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
sigaddset(&sigset,SIGALRM);
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

	// sit in this loop processing messages from the queue
	while (g_shutdown == 0)
	{
	wagon = g_messagequeue->GrabMessage();
	if (wagon == NULL) continue;

		switch(wagon->command)
		{
		case MSG_SHUTDOWN:
			g_shutdown = 1;
			break;

		case MSG_CREATE:
			LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION CREATE %" PRIu64 "\n",wagon->index);

			// session object should have been created by the netclient thread
			session = dynamic_cast<SessionObject*>(g_sessiontable->SearchObject(wagon->index));

				// missing session means something has gone haywire
				if (session == NULL)
				{
				sysmessage(LOG_WARNING,"MSG_CREATE: Unable to locate %" PRIu64 " in session table\n",wagon->index);
				break;
				}

			// create the vineyard connection state object
			ret = navl_conn_create(l_navl_handle,&session->clientinfo,&session->serverinfo,session->GetNetProtocol(),&session->vinestat);

				if (ret != 0)
				{
				sysmessage(LOG_ERR,"Error %d returned from navl_conn_create(%" PRIu64 ")\n",navl_error_get(l_navl_handle),wagon->index);
				g_sessiontable->DeleteObject(session);
				}

				else
				{
				log_vineyard(session,"CREATE",0,NULL,0);
				}

			break;

		case MSG_REMOVE:
			LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION REMOVE %" PRIu64 "\n",wagon->index);

			// find the session object in the hash table
			session = dynamic_cast<SessionObject*>(g_sessiontable->SearchObject(wagon->index));

				// missing session means something has gone haywire
				if (session == NULL)
				{
				sysmessage(LOG_WARNING,"MSG_REMOVE: Unable to locate %" PRIu64 " in session table\n",wagon->index);
				break;
				}

			// destroy the vineyard connection state object
			ret = navl_conn_destroy(l_navl_handle,session->vinestat);
			if (ret != 0) sysmessage(LOG_ERR,"Error %d returned from navl_conn_destroy(%" PRIu64 ")\n",navl_error_get(l_navl_handle),wagon->index);
			else log_vineyard(session,"DESTROY",0,NULL,0);

			// delete the session object from the hash table
			g_sessiontable->DeleteObject(session);
			break;

		case MSG_CLIENT:
			LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION CLIENT %" PRIu64 " %d BYTES\n",wagon->index,wagon->length);

			// if data packets are stale we throw them away in hopes of catching up
			current = time(NULL);
			if (current > (wagon->timestamp + cfg_packet_timeout)) msg_timedrop++;

			// find the session object in the hash table
			session = dynamic_cast<SessionObject*>(g_sessiontable->SearchObject(wagon->index));

				// missing session means something has gone haywire
				if (session == NULL)
				{
				sysmessage(LOG_WARNING,"MSG_CLIENT: Unable to locate %" PRIu64 " in session table\n",wagon->index);
				break;
				}

			log_vineyard(session,"PRE_c2s",CLIENT_to_SERVER,wagon->buffer,wagon->length);

			// send the traffic to vineyard for classification
			ret = navl_classify(l_navl_handle,NAVL_ENCAP_NONE,wagon->buffer,wagon->length,session->vinestat,CLIENT_to_SERVER,navl_callback,session);
			if (ret != 0) sysmessage(LOG_ERR,"Error %d returned from navl_classify(CLIENT:%" PRIu64 ")\n",navl_error_get(l_navl_handle),wagon->index);
			else log_vineyard(session,"POST_c2s",CLIENT_to_SERVER,wagon->buffer,wagon->length);

			break;

		case MSG_SERVER:
			LOGMESSAGE(CAT_SESSION,LOG_DEBUG,"SESSION SERVER %" PRIu64 " %d BYTES\n",wagon->index,wagon->length);

			// if data packets are stale we throw them away in hopes of catching up
			current = time(NULL);
			if (current > (wagon->timestamp + cfg_packet_timeout)) msg_timedrop++;

			// find the session object in the hash table
			session = dynamic_cast<SessionObject*>(g_sessiontable->SearchObject(wagon->index));

				// missing session means something has gone haywire
				if (session == NULL)
				{
				sysmessage(LOG_WARNING,"MSG_SERVER: Unable to locate %" PRIu64 " in session table\n",wagon->index);
				break;
				}

			log_vineyard(session,"PRE_s2c",SERVER_to_CLIENT,wagon->buffer,wagon->length);

			// send the traffic to vineyard for classification
			ret = navl_classify(l_navl_handle,NAVL_ENCAP_NONE,wagon->buffer,wagon->length,session->vinestat,SERVER_to_CLIENT,navl_callback,session);
			if (ret != 0) sysmessage(LOG_ERR,"Error %d returned from navl_classify(SERVER:%" PRIu64 ")\n",navl_error_get(l_navl_handle),wagon->index);
			else log_vineyard(session,"POST_s2c",SERVER_to_CLIENT,wagon->buffer,wagon->length);

			break;

		case MSG_DEBUG:
			vineyard_debug((char *)wagon->buffer);
			break;

		default:
			sysmessage(LOG_WARNING,"Unknown thread message received = %c\n",wagon->command);
		}

	// always delete the wagon in which the message arrived
	delete(wagon);
	}

// call our vineyard shutdown function
vineyard_shutdown();

sysmessage(LOG_INFO,"The classify thread has finished\n");
return(NULL);
}
/*--------------------------------------------------------------------------*/
int navl_callback(navl_handle_t handle,navl_result_t result,navl_state_t state,navl_conn_t conn,void *arg,int error)
{
navl_iterator_t		it;
SessionObject		*session = (SessionObject *)arg;
char				namestr[256];
char				protochain[256];
int					appid,value;
int					confidence;

// if the session object passed is null we can't update
// this should never happen but we check just in case
if (session == NULL) return(0);

log_vineyard(session,"CALLBACK",0,NULL,0);

	// keep track of errors returned by vineyard
	if (error != 0)
	{
		switch (error)
		{
		case ENOMEM:	err_nomem++;	break;
		case ENOBUFS:	err_nobufs++;	break;
		case ENOSR:		err_nosr++;		break;
		case ENOTCONN:	err_notconn++;	break;
		default:		err_unknown++;	break;
		}

	// if there was an error return but keep tracking the session
	return(0);
	}

// get the application id and confidence
confidence = 0;
appid = navl_app_get(handle,result,&confidence);

	// if the appid is out of bounds return but keep tracking the session
	if ((appid < 0) || (appid > g_protocount))
	{
	vineyard_appfail++;
	return(0);
	}

// clear local variables that we fill in while building the protochain
protochain[0] = 0;

	// build the protochain
	for(it = navl_proto_first(handle,result);navl_proto_valid(handle,it);navl_proto_next(handle,it))
	{
	// get the protocol index
	value = navl_proto_get_index(handle,it);

		// if the protocol is out of bounds just use question marks
		if ((value < 0) || (value > g_protocount))
		{
		strncat(protochain,"/???",sizeof(protochain)-1);
		vineyard_protofail++;
		continue;
		}

	// append the protocol name to the chain
	strncat(protochain,"/",sizeof(protochain)-1);
	strncat(protochain,g_protostats[value]->protocol_name,sizeof(protochain)-1);
	g_protostats[value]->packet_count++;
	}

// update the session object with the new information
session->UpdateObject(g_protostats[appid]->protocol_name,protochain,confidence,state);

LOGMESSAGE(CAT_UPDATE,LOG_DEBUG,"CLASSIFY UPDATE (V:%" PRIXPTR ") %s\n",conn,session->GetObjectString(namestr,sizeof(namestr)));

// continue tracking the session
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

// we can't initialize our l_attr_xxx values during startup because the values
// returned by vineyard are different for each thread so to work around this
// we set them as invalid during startup and init the first time we are called
if (l_attr_facebook_app == INVALID_VALUE) l_attr_facebook_app = navl_attr_key_get(handle,l_name_facebook_app);
if (l_attr_tls_hostname == INVALID_VALUE) l_attr_tls_hostname = navl_attr_key_get(handle,l_name_tls_hostname);

	// check for the facebook application name
	if (attr_type == l_attr_facebook_app)
	{
	memcpy(detail,attr_value,attr_length);
	detail[attr_length] = 0;
	}

	// check for the tls host name
	else if (attr_type == l_attr_tls_hostname)
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
session->UpdateDetail(detail);

LOGMESSAGE(CAT_UPDATE,LOG_DEBUG,"CLASSIFY DETAIL %s\n",session->GetObjectString(namestr,sizeof(namestr)));
}
/*--------------------------------------------------------------------------*/
int vineyard_startup(void)
{
const char	*check;
char		work[32];
int			problem = 0;
int			junk,ret;
int			l,x,y;

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

// disable session timeout for TCP and UDP since we do the session management
if (vineyard_config("tcp.timeout",0) != 0) return(2);
if (vineyard_config("udp.timeout",0) != 0) return(3);

// set the vineyard system loglevel parameter
if (vineyard_config("system.loglevel",cfg_navl_debug) != 0) return(4);

// set the number of of http request+response pairs to analyze before giving up
if (vineyard_config("http.maxpersist",cfg_http_limit) != 0) return(5);

// enable IP fragment processing
if (vineyard_config("ip.defrag",cfg_navl_defrag) != 0) return(6);

// set all the low level skype parameters
if (vineyard_config("skype.confidence_thresh",cfg_skype_confidence_thresh) != 0) return(7);
if (vineyard_config("skype.packet_thresh",cfg_skype_packet_thresh) != 0) return(8);
if (vineyard_config("skype.probe_thresh",cfg_skype_probe_thresh) != 0) return(9);
if (vineyard_config("skype.random_thresh",cfg_skype_random_thresh) != 0) return(10);
if (vineyard_config("skype.require_history",cfg_skype_require_history) != 0) return(11);
if (vineyard_config("skype.seq_cache_time",cfg_skype_seq_cache_time) != 0) return(12);

// initialize the vineyard handle for the active thread
ret = navl_init(l_navl_handle);

	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from navl_init()\n",ret);
	return(13);
	}

if ((navl_attr_callback_set(l_navl_handle,l_name_facebook_app,attr_callback) != 0)) problem|=0x01;
if ((navl_attr_callback_set(l_navl_handle,l_name_tls_hostname,attr_callback) != 0)) problem|=0x02;

	if (problem != 0)
	{
	sysmessage(LOG_ERR,"Error 0x%02X enabling metadata callbacks\n",problem);
	return(14);
	}

// get the total number of protocols from the vineyard library
ret = navl_proto_max_index(l_navl_handle);

	if (ret == -1)
	{
	sysmessage(LOG_ERR,"Error calling navl_proto_max_index()\n");
	return(15);
	}

// create the array of protocol statistics
g_protocount = (ret + 1);
g_protostats = (protostats **)malloc(g_protocount * sizeof(protostats *));

        // get the name of each protocol add create new protolist entry
        for(x = 0;x < g_protocount;x++)
        {
        work[0] = 0;
        check = navl_proto_get_name(l_navl_handle,x,work,sizeof(work));
		l = strlen(work);
		junk = 0;

			if ((check == NULL) || (l == 0))
			{
			if (x != 0) sysmessage(LOG_WARNING,"Empty name returned for protocol %d\n",x);
			strcpy(work,"UNKNOWN");
			}

			for(y = 0;y < l;y++)
			{
			if (isascii(work[y]) != 0) continue;
			work[y] = '?';
			junk++;
			}

			if (junk != 0)
			{
			sysmessage(LOG_WARNING,"Invalid name returned for protocol %d (%s)\n",x,work);
			}

        g_protostats[x] = (protostats *)malloc(sizeof(protostats));
        strcpy(g_protostats[x]->protocol_name,work);
        g_protostats[x]->packet_count = 0;
        }

return(0);
}
/*--------------------------------------------------------------------------*/
void vineyard_shutdown(void)
{
int		x;

// finalize the vineyard library
navl_fini(l_navl_handle);

// shut down the vineyard engine
navl_close(l_navl_handle);

// free the protostats
for(x = 0;x < g_protocount;x++) free(g_protostats[x]);
free(g_protostats);
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
void vineyard_debug(const char *dumpfile)
{
FILE		*stream;

// open the dumpfile for append
stream = fopen(dumpfile,"a");

// set file descriptor to capture output from vineyard
l_navl_logfile = fileno(stream);

// dump the vineyard diagnostic info and include calls
// to fflush since we're passing the file descriptor

fprintf(stream,"========== VINEYARD SYSTEM INFO ==========\r\n");
fflush(stream);
navl_diag(l_navl_handle,"SYSTEM","");

fprintf(stream,"========== VINEYARD TCP INFO ==========\r\n");
fflush(stream);
navl_diag(l_navl_handle,"TCP","");

fprintf(stream,"========== VINEYARD UDP INFO ==========\r\n");
fflush(stream);
navl_diag(l_navl_handle,"UDP","");

fprintf(stream,"========== VINEYARD CONFIG INFO ==========\r\n");
fflush(stream);
navl_config_dump_verbose(l_navl_handle);

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
void log_vineyard(SessionObject *session,const char *message,int direction,void *rawdata,int rawsize)
{
const char		*pname;
const char		*work;
char			clientaddr[32];
char			serveraddr[32];

// do nothing if packet logging is not enabled
if ((g_debug & CAT_VINEYARD) == 0) return;

if (session->GetNetProtocol() == IPPROTO_TCP) pname = "TCP";
if (session->GetNetProtocol() == IPPROTO_UDP) pname = "UDP";

work = inet_ntop(AF_INET,&session->clientinfo.in4_addr,clientaddr,sizeof(clientaddr));
if (work == NULL) strcpy(clientaddr,"xxx.xxx.xxx.xxx");

work = inet_ntop(AF_INET,&session->serverinfo.in4_addr,serveraddr,sizeof(serveraddr));
if (work == NULL) strcpy(clientaddr,"xxx.xxx.xxx.xxx");

	if (rawdata != NULL)
	{
	if (direction == CLIENT_to_SERVER) LOGMESSAGE(CAT_VINEYARD,LOG_DEBUG,"VINEYARD %s (L:%d V:%" PRIXPTR ") = %s %s:%" PRIu16 " --> %s:%" PRIu16 "\n",message,rawsize,session->vinestat,pname,clientaddr,ntohs(session->clientinfo.port),serveraddr,ntohs(session->serverinfo.port));
	if (direction == SERVER_to_CLIENT) LOGMESSAGE(CAT_VINEYARD,LOG_DEBUG,"VINEYARD %s (L:%d V:%" PRIXPTR ") = %s %s:%" PRIu16 " --> %s:%" PRIu16 "\n",message,rawsize,session->vinestat,pname,serveraddr,ntohs(session->serverinfo.port),clientaddr,ntohs(session->clientinfo.port));
	}

	else
	{
	LOGMESSAGE(CAT_VINEYARD,LOG_DEBUG,"VINEYARD %s (V:%" PRIXPTR ") = %s %s:%" PRIu16 " --> %s:%" PRIu16 "\n",message,session->vinestat,pname,clientaddr,ntohs(session->clientinfo.port),serveraddr,ntohs(session->serverinfo.port));
	}
}
/*--------------------------------------------------------------------------*/

