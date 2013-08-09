// CLASSD.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2013 Untangle, Inc.
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
pthread_attr_t		attr;
rlimit				core;
fd_set				tester;
time_t				currtime,lasttime;
int					ret,x;

printf("[ CLASSD ] Untangle Traffic Classification Engine Version %s\n",VERSION);

strcpy(g_cfgfile,"untangle-classd.conf");
gettimeofday(&g_runtime,NULL);
load_configuration();

// set the core dump file size limit
core.rlim_cur = 0x40000000;
core.rlim_max = 0x40000000;
setrlimit(RLIMIT_CORE,&core);

	for(x = 1;x < argc;x++)
	{
	if (strncasecmp(argv[x],"-F",2) == 0) g_nofork++;
	if (strncasecmp(argv[x],"-L",2) == 0) g_console++;

		if (strncasecmp(argv[x],"-D",2) == 0)
		{
		g_debug = atoi(&argv[x][2]);
		if (g_debug == 0) g_debug = 0xFFFF;
		}
	}

// change directory to path for core dump files
if (g_console == 0) chdir(cfg_core_path);

// get the default application stack size so
// we can set the same stack size for threads
pthread_attr_init(&attr);
pthread_attr_getstacksize(&attr,&g_stacksize);
pthread_attr_destroy(&attr);

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

// grab the profile itimer value for thread profiling support
getitimer(ITIMER_PROF,&g_itimer);

sysmessage(LOG_NOTICE,"STARTUP Untangle CLASSd %d-Bit Version %s Build %s\n",(int)sizeof(void*)*8,VERSION,BUILDID);

if (g_console != 0) sysmessage(LOG_NOTICE,"Running on console - Use ENTER or CTRL+C to terminate\n");

// create the main message queue
g_messagequeue = new MessageQueue();

// create our session table
g_sessiontable = new HashTable(cfg_hash_buckets);

// start the vineyard classification thread
sem_init(&g_classify_sem,0,0);
pthread_attr_init(&attr);
pthread_attr_setstacksize(&attr,g_stacksize);
ret = pthread_create(&g_classify_tid,NULL,classify_thread,NULL);
pthread_attr_destroy(&attr);

	if (ret != 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from pthread_create(classify)\n",ret);
	g_shutdown = 1;
	}

// wait for the thread to signal init complete
sem_wait(&g_classify_sem);

// create the network server
g_netserver = new NetworkServer();
g_netserver->BeginExecution();

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
		ret = g_sessiontable->PurgeStaleObjects(currtime);
		LOGMESSAGE(CAT_LOGIC,LOG_DEBUG,"Removed %d stale objects from session table\n",ret);
		periodic_checkup();
		}

		if (g_logrecycle != 0)
		{
		logrecycle();
		g_logrecycle = 0;
		}
	}

// set the global shutdown flag
g_shutdown = 1;

// post a shutdown message to the main message queue
g_messagequeue->PushMessage(new MessageWagon(MSG_SHUTDOWN));

// the five second alarm gives all threads time to shut down cleanly
// if any get stuck the abort() in the signal handler should do the trick
alarm(5);
pthread_join(g_classify_tid,NULL);
alarm(0);

// clean up the thread semaphores
sem_destroy(&g_classify_sem);

// cleanup the network server
delete(g_netserver);

// cleanup all the global objects we created
delete(g_sessiontable);
delete(g_messagequeue);

sysmessage(LOG_NOTICE,"GOODBYE Untangle CLASSd Version %s Build %s\n",VERSION,BUILDID);

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
	case SIGALRM:
		abort();
		break;

	case SIGTERM:
	case SIGQUIT:
	case SIGINT:
		signal(sigval,sighandler);
		g_shutdown = 1;
		break;

	case SIGHUP:
		signal(sigval,sighandler);
		g_logrecycle = 1;
		break;
	}
}
/*--------------------------------------------------------------------------*/
void logrecycle(void)
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
void logmessage(int category,int priority,const char *format,...)
{
va_list			args;
char			message[1024];

if ((priority == LOG_DEBUG) && (g_debug == 0)) return;
if ((g_debug & category) == 0) return;

va_start(args,format);
vsnprintf(message,sizeof(message),format,args);
va_end(args);

rawmessage(priority,message);
}
/*--------------------------------------------------------------------------*/
void sysmessage(int priority,const char *format,...)
{
va_list			args;
char			message[1024];

va_start(args,format);
vsnprintf(message,sizeof(message),format,args);
va_end(args);

rawmessage(priority,message);
}
/*--------------------------------------------------------------------------*/
void hexmessage(int category,int priority,const void *buffer,int size)
{
const unsigned char		*data;
char					*message;
int						loc;
int						x;

if ((priority == LOG_DEBUG) && (g_debug == 0)) return;
if ((g_debug & category) == 0) return;

message = (char *)malloc((size * 3) + 4);
data = (const unsigned char *)buffer;

	for(x = 0;x < size;x++)
	{
	loc = (x * 3);
	if (x == 0) sprintf(&message[loc],"%02X ",data[x]);
	else sprintf(&message[loc],"%02X ",data[x]);
	}

loc = (size * 3);
strcpy(&message[loc],"\n");
rawmessage(priority,message);
free(message);
}
/*--------------------------------------------------------------------------*/
void rawmessage(int priority,const char *message)
{
struct timeval	nowtime;
struct tm		*today;
time_t			value;
double			rr,nn,ee;
char			string[32];

if ((priority == LOG_DEBUG) && (g_debug == 0)) return;

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
}
/*--------------------------------------------------------------------------*/
char *nowtimestr(char *target)
{
struct tm	*today;
time_t		value;

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

return(target);
}
/*--------------------------------------------------------------------------*/
char *runtimestr(char *target)
{
struct timeval	nowtime;
int				dd,hh,mm,ss;
int				dt,pp,ww;

gettimeofday(&nowtime,NULL);
dt = (nowtime.tv_sec - g_runtime.tv_sec);

dd = (dt / 86400);
pp = (dt % 86400);
hh = (pp / 3600);
ww = (pp % 3600);
mm = (ww / 60);
ss = (ww % 60);

sprintf(target,"%d Days + %02d:%02d:%02d",dd,hh,mm,ss);

return(target);
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
char *pad(char *target,u_int64_t value,int width)
{
char	source[256];
int		l,x,y;

sprintf(source,"%"PRI64u,value);

l = strlen(source);

	for(x = y = 0;x < l;x++)
	{
	if ((x > 0) && ((x % 3) == (l % 3))) target[y++] = ',';
	target[y++] = source[x];
	}

while (y < width) target[y++] = ' ';
target[y] = 0;
return(target);
}
/*--------------------------------------------------------------------------*/
void load_configuration(void)
{
FILE		*cfg;
char		**filedata;
char		*check;
char		work[1024];
int			total,len,x;

// open the config file
cfg = fopen("/etc/default/untangle-classd","r");
if (cfg == NULL) return;

// allocate an array of pointers to hold each line
filedata = (char **)calloc(1024,sizeof(char *));
total = 0;

	// grab all the data from the config file
	for(;;)
	{
	check = fgets(work,sizeof(work),cfg);
	if (check == NULL) break;

	// ignore lines that start with hash or space
	if (check[0] == '#') continue;
	if (isspace(check[0])) continue;

	// allocate some memory and save the line
	len = strlen(work);
	filedata[total] = (char *)malloc(len + 1);
	strcpy(filedata[total],work);
	total++;
	}

fclose(cfg);

grab_config_item(filedata,"CLASSD_LOG_PATH",cfg_log_path,sizeof(cfg_log_path),"/var/log/untangle-classd");
grab_config_item(filedata,"CLASSD_LOG_FILE",cfg_log_file,sizeof(cfg_log_file),"/var/log/untangle-classd/classd.log");
grab_config_item(filedata,"CLASSD_DUMP_PATH",cfg_dump_path,sizeof(cfg_dump_path),"/tmp");
grab_config_item(filedata,"CLASSD_CORE_PATH",cfg_core_path,sizeof(cfg_core_path),"/usr/share/untangle-classd");
grab_config_item(filedata,"CLASSD_PLUGIN_PATH",cfg_navl_plugins,sizeof(cfg_navl_plugins),"/usr/share/untangle-classd/plugins");

grab_config_item(filedata,"CLASSD_FACEBOOK_SUBCLASS",work,sizeof(work),"1");
cfg_facebook_subclass = atoi(work);

grab_config_item(filedata,"CLASSD_SKYPE_PACKETTHRESH",work,sizeof(work),"4");
cfg_skype_packet_thresh = atoi(work);

grab_config_item(filedata,"CLASSD_SKYPE_RANDOMTHRESH",work,sizeof(work),"95");
cfg_skype_random_thresh = atoi(work);

grab_config_item(filedata,"CLASSD_SKYPE_PROBETHRESH",work,sizeof(work),"2");
cfg_skype_probe_thresh = atoi(work);

grab_config_item(filedata,"CLASSD_SKYPE_REQUIREHIST",work,sizeof(work),"1");
cfg_skype_require_history = atoi(work);

grab_config_item(filedata,"CLASSD_HASH_BUCKETS",work,sizeof(work),"99991");
cfg_hash_buckets = atoi(work);

grab_config_item(filedata,"CLASSD_MEMORY_LIMIT",work,sizeof(work),"262144");
cfg_mem_limit = atoi(work);

grab_config_item(filedata,"CLASSD_IP_DEFRAG",work,sizeof(work),"1");
cfg_navl_defrag = atoi(work);

grab_config_item(filedata,"CLASSD_LIBRARY_DEBUG",work,sizeof(work),"0");
cfg_navl_debug = atoi(work);

grab_config_item(filedata,"CLASSD_TCP_TIMEOUT",work,sizeof(work),"7200");
cfg_tcp_timeout = atoi(work);

grab_config_item(filedata,"CLASSD_UDP_TIMEOUT",work,sizeof(work),"600");
cfg_udp_timeout = atoi(work);

grab_config_item(filedata,"CLASSD_HTTP_LIMIT",work,sizeof(work),"0");
cfg_http_limit = atoi(work);

grab_config_item(filedata,"CLASSD_CLIENT_PORT",work,sizeof(work),"8123");
cfg_client_port = atoi(work);

grab_config_item(filedata,"CLASSD_PACKET_TIMEOUT",work,sizeof(work),"4");
cfg_packet_timeout = atoi(work);

grab_config_item(filedata,"CLASSD_PACKET_MAXIMUM",work,sizeof(work),"1000000");
cfg_packet_maximum = atoi(work);

for(x = 0;x < total;x++) free(filedata[x]);
free(filedata);
}
/*--------------------------------------------------------------------------*/
const char *grab_config_item(char** const filedata,const char *search,char *target,int size,const char *init)
{
char		worker[1024];
char		lookup[256];
char		*find;
int			len,x;

if (target == NULL) abort();

// start with the default value in target
if (init != NULL) strcpy(target,init);
else target[0] = 0;

// if any args look invalid just return
if (filedata == NULL) return(target);
if (search == NULL) return(target);
if (size < 1) return(target);

// make a complete search string
len = sprintf(lookup,"%s=",search);

find = NULL;

	for(x = 0;filedata[x] != NULL;x++)
	{
	find = strcasestr(filedata[x],lookup);
	if (find == NULL) continue;

	// make a local copy we can play with
	strcpy(worker,filedata[x]);
	find = strchr(worker,'=');
	if (find == NULL) continue;
	*find++ = 0;

	// ignore if there are any comment characters on left side
	if (strchr(worker,'#') != NULL) continue;
	break;
	}

if (find == NULL) return(target);

// skip over any leading spaces
while ((*find != 0) && (isspace(*find) != 0)) find++;

// copy the value to the target buffer
strcpy(target,find);

// get rid of any trailing space or comment characters
find = target;
while ((*find != 0) && (isspace((int)*find) == 0) && (*find != '#')) find++;

// set the null terminator at the end of the string
*find = 0;

return(target);
}
/*--------------------------------------------------------------------------*/
void periodic_checkup(void)
{
pid_t		mypid;
char		filename[256];
char		buffer[4096];
char		*find;
int			fid,len,mem;

// get our process id and open our status file
mypid = getpid();
sprintf(filename,"/proc/%d/status",mypid);
fid = open(filename,O_RDONLY);
if (fid < 0) return;

// read our status information from the file
len = read(fid,buffer,sizeof(buffer));
close(fid);
if (len < 0) return;

// make sure the buffer is null terminated
buffer[len] = 0;

// look for the VmRSS label and extract the size
find = strstr(buffer,"VmRSS:");
if (find == NULL) return;
find = (find + 6);
while ((isspace(*find)) && (*find != 0)) find++;
mem = atoi(find);

	// if we are below the limit we just return
	if (mem < cfg_mem_limit)
	{
	LOGMESSAGE(CAT_LOGIC,LOG_DEBUG,"Memory size %d kB is below the %d kB limit\n",mem,cfg_mem_limit);
	return;
	}

sysmessage(LOG_ERR,"Setting shutdown flag due to high memory usage of %d kB\n",mem);
g_shutdown++;
}
/*--------------------------------------------------------------------------*/

