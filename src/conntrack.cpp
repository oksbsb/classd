// CONNTRACK.CPP
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
// vars for the conntrack thread
void conntrack_sighandler(int sigval);
struct nfct_handle *nfcth;
/*--------------------------------------------------------------------------*/
void* conntrack_thread(void *arg)
{
sigset_t	sigset;
int			ret;

sysmessage(LOG_INFO,"The conntrack thread is starting\n");

// set the itimer value of the main thread which is required
// for gprof to work properly with multithreaded applications
setitimer(ITIMER_PROF,&g_itimer,NULL);

// start by masking all signals
sigfillset(&sigset);
pthread_sigmask(SIG_BLOCK,&sigset,NULL);

// now we allow only the USR1 and PROF signals
sigemptyset(&sigset);
sigaddset(&sigset,SIGUSR1);
sigaddset(&sigset,SIGPROF);
pthread_sigmask(SIG_UNBLOCK,&sigset,NULL);

// setup handler for USR1 signal which allows us to break
// out of the nfct_catch function during daemon shutdown
signal(SIGUSR1,conntrack_sighandler);

// call our conntrack startup function
ret = conntrack_startup();

// signal the startup complete semaphore
sem_post(&g_conntrack_sem);

	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from conntrack_startup()\n",ret);
	g_shutdown = 1;
	return(NULL);
	}

	// the nfct_catch function should only return if it receives a signal
	// other than EINTR or if NFCT_CB_STOP is returned from the callback
	while (g_shutdown == 0)
	{
	nfct_catch(nfcth);
	}

// call our conntrack shutdown function
conntrack_shutdown();

sysmessage(LOG_INFO,"The conntrack thread has terminated\n");
return(NULL);
}
/*--------------------------------------------------------------------------*/
void conntrack_sighandler(int sigval)
{
int		fd;

// close the conntrack fd to break out of nfct_catch
fd = nfct_fd(nfcth);
close(fd);
}
/*--------------------------------------------------------------------------*/
int conn_callback(enum nf_conntrack_msg_type type,struct nf_conntrack *ct,void *data)
{
TrackerObject	*tracker;
u_int32_t		orig_saddr,repl_saddr;
u_int32_t		orig_daddr,repl_daddr;
u_int16_t		orig_sport,repl_sport;
u_int16_t		orig_dport,repl_dport;
u_int8_t		orig_proto,repl_proto;
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

// check our special ignore flags
if ((orig_proto == IPPROTO_TCP) && (g_skiptcp != 0)) return(NFCT_CB_CONTINUE);
if ((orig_proto == IPPROTO_UDP) && (g_skipudp != 0)) return(NFCT_CB_CONTINUE);

// set our protocol name or return on stuff we don't care about
if (orig_proto == IPPROTO_TCP) pname = "TCP";
else if (orig_proto == IPPROTO_UDP) pname = "UDP";
else return(NFCT_CB_CONTINUE);

// get the attributes we need
orig_saddr = nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_SRC);
orig_sport = nfct_get_attr_u16(ct,ATTR_ORIG_PORT_SRC);
orig_daddr = nfct_get_attr_u32(ct,ATTR_ORIG_IPV4_DST);
orig_dport = nfct_get_attr_u16(ct,ATTR_ORIG_PORT_DST);
repl_saddr = nfct_get_attr_u32(ct,ATTR_REPL_IPV4_SRC);
repl_sport = nfct_get_attr_u16(ct,ATTR_REPL_PORT_SRC);
repl_daddr = nfct_get_attr_u32(ct,ATTR_REPL_IPV4_DST);
repl_dport = nfct_get_attr_u16(ct,ATTR_REPL_PORT_DST);

// extract the client and server addresses
inet_ntop(AF_INET,&orig_saddr,orig_sname,sizeof(orig_sname));
inet_ntop(AF_INET,&orig_daddr,orig_dname,sizeof(orig_dname));
inet_ntop(AF_INET,&repl_saddr,repl_sname,sizeof(repl_sname));
inet_ntop(AF_INET,&repl_daddr,repl_dname,sizeof(repl_dname));

sprintf(finder,"%s-%s:%u-%s:%u",pname,repl_sname,ntohs(repl_sport),repl_dname,ntohs(repl_dport));

	if (type & NFCT_T_NEW)
	{
	tracker = new TrackerObject(orig_proto,finder);
	tracker->UpdateObject(orig_saddr,orig_sport,orig_daddr,orig_dport);
	g_trackertable->InsertObject(tracker);
	LOGMESSAGE(CAT_TRACKER,LOG_DEBUG,"TRACKER INSERT %s\n",tracker->GetObjectString(namestr,sizeof(namestr)));
	}

	if (type & NFCT_T_UPDATE)
	{
	tracker = dynamic_cast<TrackerObject*>(g_trackertable->SearchObject(finder));
	if (tracker != NULL) tracker->UpdateObject(orig_saddr,orig_sport,orig_daddr,orig_dport);
	LOGMESSAGE(CAT_TRACKER,LOG_DEBUG,"TRACKER UPDATE %s\n",tracker->GetObjectString(namestr,sizeof(namestr)));
	}

	if (type & NFCT_T_DESTROY)
	{
	tracker = dynamic_cast<TrackerObject*>(g_trackertable->SearchObject(finder));
	if (tracker != NULL) g_trackertable->ExpireObject(tracker);
	LOGMESSAGE(CAT_TRACKER,LOG_DEBUG,"TRACKER EXPIRE %s\n",tracker->GetObjectString(namestr,sizeof(namestr)));
	}

return(NFCT_CB_CONTINUE);
}
/*--------------------------------------------------------------------------*/
int conntrack_startup(void)
{
int		ret;

// open a conntrack netlink handler
nfcth = nfct_open(CONNTRACK,NFNL_SUBSYS_CTNETLINK);

	if (nfcth == NULL)
	{
	sysmessage(LOG_ERR,"Error %d returned from nfct_open()\n",errno);
	g_shutdown = 1;
	return(1);
	}

// register the conntrack callback
ret = nfct_callback_register(nfcth,NFCT_T_ALL,conn_callback,NULL);

	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from nfct_callback_register()\n",errno);
	g_shutdown = 1;
	return(2);
	}

return(0);
}
/*--------------------------------------------------------------------------*/
void conntrack_shutdown(void)
{
// unregister the callback handler
nfct_callback_unregister(nfcth);

// close the conntrack netlink handler
nfct_close(nfcth);
}
/*--------------------------------------------------------------------------*/

