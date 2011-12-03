// CLASSD.C
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#define DATALOC
#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
const char *month[12] = { "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec" };
const char *weekday[7] = { "Sun","Mon","Tue","Wed","Thu","Fri","Sat" };
/*--------------------------------------------------------------------------*/
int main(int argc,char *argv[])
{
struct timeval		tv;
fd_set				tester;
time_t				currtime,lasttime;
int					ret,x;

printf("[ CLASSD ] Untangle Traffic Classification Engine Version %s\n",VERSION);
strcpy(g_cfgfile,"untangle-classd.conf");
gettimeofday(&g_runtime,NULL);
load_configuration();

	for(x = 1;x < argc;x++)
	{
	if (strncasecmp(argv[x],"-D",2) == 0) g_debug++;
	if (strncasecmp(argv[x],"-F",2) == 0) g_nofork++;
	if (strncasecmp(argv[x],"-L",2) == 0) g_console++;
	}

	if (g_console == 0)
	{
	// not running on the console so open our log file
	mkdir(cfg_log_path,0755);
	g_logfile = fopen(cfg_log_file,"a");

	// if there was an error then fallback to using syslog
	if (g_logfile == NULL) openlog("classd",LOG_NDELAY,LOG_DAEMON);

	if (g_nofork == 0) ret = fork();
	else ret = 0;

		if (ret > 0)
		{
		printf("[ CLASSD ] Daemon %d started successfully\n\n",ret);
		return(0);
		}

		if (ret < 0)
		{
		printf("[ CLASSD ] Error %d on fork daemon process\n\n",errno);
		return(1);
		}

	// since we are running as a daemon we need to disconnect from the console
	freopen("/dev/null","r",stdin);
	freopen("/dev/null","w",stdout);
	freopen("/dev/null","w",stderr);
	}

signal(SIGALRM,sighandler);
signal(SIGTERM,sighandler);
signal(SIGQUIT,sighandler);
signal(SIGINT,sighandler);
signal(SIGHUP,sighandler);

signal(SIGSEGV,sighandler);
signal(SIGILL,sighandler);
signal(SIGFPE,sighandler);

// grab the profile itimer value for thread profiling support
getitimer(ITIMER_PROF,&g_itimer);

logmessage(LOG_NOTICE,"STARTUP Untangle CLASSd Version %s Build %s\n",VERSION,BUILDID);
if (g_console != 0) logmessage(LOG_NOTICE,"Running on console - Use ENTER or CTRL+C to terminate\n");

// allocate our connection hashtable
g_conntable = new HashTable(cfg_hash_buckets);

// create our network server
g_netserver = new NetworkServer();
g_netserver->BeginExecution();

// start the netqueue filter handler thread
ret = pthread_create(&g_netfilter_tid,NULL,netfilter_thread,NULL);

	if (ret != 0)
	{
	logmessage(LOG_ERR,"Error %d returned from pthread_create(netfilter)\n",ret);
	g_shutdown = 1;
	}

// initialize cleanup timers
currtime = lasttime = time(NULL);

	while (g_shutdown == 0)
	{
		// if running on the console check for keyboard input
		if (g_console != 0)
		{
		FD_ZERO(&tester);
		FD_SET(fileno(stdin),&tester);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		ret = select(fileno(stdin)+1,&tester,NULL,NULL,&tv);
		if ((ret == 1) && (FD_ISSET(fileno(stdin),&tester) != 0)) break;
		}

		// in daemon mode we just snooze for a bit
		else
		{
		sleep(1);
		}

	// periodically perform hashtable cleanup
	currtime = time(NULL);

		if (currtime > (lasttime + 60))
		{
		lasttime = currtime;
		ret = g_conntable->PurgeStaleObjects(currtime);
		logmessage(LOG_DEBUG,"Removed %d stale objects from hashtable\n",ret);
		}

		if (g_recycle != 0)
		{
		recycle();
		g_recycle = 0;
		}
	}

// set the global shutdown flag
g_shutdown = 1;

// wait for the filter thread to finish
pthread_join(g_netfilter_tid,NULL);

// cleanup the network server and connection hashtable
delete(g_netserver);
delete(g_conntable);

logmessage(LOG_NOTICE,"GOODBYE Untangle CLASSd Version %s Build %s\n",VERSION,BUILDID);

	if (g_console == 0)
	{
	if (g_logfile != NULL) fclose(g_logfile);
	else closelog();
	}

return(0);
}
/*--------------------------------------------------------------------------*/
void sighandler(int sigval)
{
	switch(sigval)
	{
	case SIGTERM:
	case SIGQUIT:
	case SIGINT:
		signal(sigval,sighandler);
		g_shutdown = 1;
		break;

	case SIGHUP:
		signal(sigval,sighandler);
		g_recycle = 1;
		break;

	case SIGSEGV:
		g_shutdown = 2;
		abort();
		break;

	case SIGILL:
		g_shutdown = 2;
		abort();
		break;

	case SIGFPE:
		g_shutdown = 2;
		abort();
		break;
	}
}
/*--------------------------------------------------------------------------*/
void recycle(void)
{
// if running on console just return
if (g_console != 0) return;

	// if we couldn't initially open our configured log file
	// then recycle our connection to the syslog facility
	if (g_logfile == NULL)
	{
	closelog();
	openlog("classd",LOG_NDELAY,LOG_DAEMON);
	return;
	}

// the configured log file is valid so close and re-open
fclose(g_logfile);
mkdir(cfg_log_path,0755);
g_logfile = fopen(cfg_log_file,"a");

// if there was an error then fallback to using syslog
if (g_logfile == NULL) openlog("classd",LOG_NDELAY,LOG_DAEMON);
}
/*--------------------------------------------------------------------------*/
void logmessage(int priority,const char *format,...)
{
struct timeval	nowtime;
struct tm		*today;
va_list			args;
time_t			value;
double			rr,nn,ee;
char			message[1024];
char			string[32];

if ((priority == LOG_DEBUG) && (g_debug == 0)) return;

va_start(args,format);
vsnprintf(message,sizeof(message),format,args);
va_end(args);

	// if running on the console display log messages there
	if (g_console != 0)
	{
	gettimeofday(&nowtime,NULL);

	rr = ((double)g_runtime.tv_sec * (double)1000000.00);
	rr+=(double)g_runtime.tv_usec;

	nn = ((double)nowtime.tv_sec * (double)1000000.00);
	nn+=(double)nowtime.tv_usec;

	ee = ((nn - rr) / (double)1000000.00);

	itolevel(priority,string);
	printf("[%.6f] %s %s",ee,string,message);

	fflush(stdout);
	return;
	}

	// not running on the console and couldn't open our configured
	// log file so fallback to using the syslog facility
	if (g_logfile == NULL)
	{
	syslog(priority,"%s",message);
	return;
	}

value = time(NULL);
today = localtime(&value);
itolevel(priority,string);

fprintf(g_logfile,"%s %d %02d:%02d:%02d %s ",
	month[today->tm_mon],
	today->tm_mday,
	today->tm_hour,
	today->tm_min,
	today->tm_sec,
	string);

fputs(message,g_logfile);
fflush(g_logfile);
return;
}
/*--------------------------------------------------------------------------*/
void logproblem(Problem *aProblem)
{
logmessage(LOG_WARNING,"PROBLEM:%s  RETCODE:%d\n",aProblem->string,aProblem->value);
delete(aProblem);
}
/*--------------------------------------------------------------------------*/
void timestring(char *target)
{
struct tm		*today;
time_t			value;

value = time(NULL);
today = localtime(&value);

sprintf(target,"%s, %d %s %d %02d:%02d:%02d %s",
	weekday[today->tm_wday],
	today->tm_mday,
	month[today->tm_mon],
	today->tm_year + 1900,
	today->tm_hour,
	today->tm_min,
	today->tm_sec,
	today->tm_zone);
}
/*--------------------------------------------------------------------------*/
char *itolevel(int value,char *dest)
{
if (value == LOG_EMERG)		return(strcpy(dest,"EMERGENCY"));
if (value == LOG_ALERT)		return(strcpy(dest,"ALERT"));
if (value == LOG_CRIT)		return(strcpy(dest,"CRITICAL"));
if (value == LOG_ERR)		return(strcpy(dest,"ERROR"));
if (value == LOG_WARNING)	return(strcpy(dest,"WARNING"));
if (value == LOG_NOTICE)	return(strcpy(dest,"NOTICE"));
if (value == LOG_INFO)		return(strcpy(dest,"INFO"));
if (value == LOG_DEBUG)		return(strcpy(dest,"DEBUG"));

sprintf(dest,"LOG_%d",value);
return(dest);
}
/*--------------------------------------------------------------------------*/
void load_configuration(void)
{
INIFile		*ini = NULL;
char		dotfile[256];
char		etcfile[256];

sprintf(dotfile,"./%s",g_cfgfile);
sprintf(etcfile,"/etc/%s",g_cfgfile);

	if (access(dotfile,R_OK) == 0)
	{
	printf("[ CLASSD ] Using %s for configuration\n",dotfile);
	ini = new INIFile(dotfile);
	}

	else if (access(etcfile,R_OK) == 0)
	{
	printf("[ CLASSD ] Using %s for configuration ==\n",etcfile);
	ini = new INIFile(etcfile);
	}

	else
	{
	printf("[ CLASSD ] %s\n","Using default configuration values");
	ini = new INIFile(etcfile);
	}

ini->GetItem("General","LogPath",cfg_log_path,"/var/log/untangle-classd");
ini->GetItem("General","LogFile",cfg_log_file,"/var/log/untangle-classd/classd.log");
ini->GetItem("General","TempPath",cfg_temp_path,"/dev/shm");
ini->GetItem("General","HashBuckets",cfg_hash_buckets,99991);

ini->GetItem("Vineyard","PluginPath",cfg_navl_plugins,"/usr/share/untangle-classd/plugins");
ini->GetItem("Vineyard","Connections",cfg_navl_flows,4096);
ini->GetItem("Vineyard","Defragment",cfg_navl_defrag,1);

ini->GetItem("Network","TCPTimeout",cfg_tcp_timeout,3600);
ini->GetItem("Network","UDPTimeout",cfg_udp_timeout,300);
ini->GetItem("Network","ServerPort",cfg_share_port,8123);
ini->GetItem("Network","NetfilterQueue",cfg_net_queue,1967);

delete(ini);
}
/*--------------------------------------------------------------------------*/

