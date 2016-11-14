// CLASSD.H
// Traffic Classification Engine
// Copyright (c) 2011-2013 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#ifndef VERSION
#define VERSION "TEST"
#endif

#ifndef BUILDID
#define BUILDID "0"
#endif

// This spiffy macro will only call the actual logmessage function if the
// corresponding category is enabled for logging.  This will improve
// performance since we're not needlessly calling a function that will
// simply return.  It does require that you always use a format string

#define LOGMESSAGE(cat,pri,fmt,...) if (g_debug & cat) logmessage(cat,pri,fmt,__VA_ARGS__)
/*--------------------------------------------------------------------------*/
const unsigned int CAT_LOGIC	= 0x0001;
const unsigned int CAT_CLIENT	= 0x0002;
const unsigned int CAT_UPDATE	= 0x0004;
const unsigned int CAT_SESSION	= 0x0008;
const unsigned int CAT_VINEYARD	= 0x0010;

const unsigned char MSG_DEBUG		= 'D';
const unsigned char MSG_CREATE		= 'I';
const unsigned char MSG_REMOVE		= 'R';
const unsigned char MSG_CLIENT		= 'C';
const unsigned char MSG_SERVER		= 'S';
const unsigned char MSG_SHUTDOWN	= 'X';
/*--------------------------------------------------------------------------*/
class NetworkServer;
class NetworkClient;
class MessageQueue;
class MessageWagon;
class SessionObject;
class HashObject;
class HashTable;
class WebServer;
class Problem;
/*--------------------------------------------------------------------------*/
class NetworkServer
{
public:

	NetworkServer(void);
	virtual ~NetworkServer(void);

	void BeginExecution(void);

private:

	static void* ThreadMaster(void *arg);
	void* ThreadWorker(void);
	void InsertClient(NetworkClient *aClient);
	void RemoveClient(NetworkClient *aClient);

	NetworkClient			*ClientList;
	pthread_t				ThreadHandle;
	sem_t					ThreadSignal;
	int						netsock;
};
/*--------------------------------------------------------------------------*/
class NetworkClient
{
friend class NetworkServer;

protected:

	NetworkClient(int aSock);
	virtual ~NetworkClient(void);

	int NetworkHandler(void);

	NetworkClient			*next;
	struct sockaddr_in		netaddr;
	char					netname[32];
	char					querybuff[1024];
	char					replybuff[0x8000];
	int						queryoff;
	int						replyoff;
	int						dataloc;
	int						datalen;
	int						netsock;

private:

	void BuildConfiguration(void);
	void BuildDebugInfo(void);
	void BuildHelpPage(void);
	void DumpEverything(void);
	void AdjustLogCategory(void);
	void HandleCreate(void);
	void HandleRemove(void);

	u_int64_t HandleChunk(u_int8_t argMessage);
	u_int64_t ExtractNetworkSession(const char *argBuffer);

	int ProcessRequest(void);
	int TransmitReply(void);
};
/*--------------------------------------------------------------------------*/
class MessageQueue
{
public:

	MessageQueue(void);
	virtual ~MessageQueue(void);

	void PushMessage(MessageWagon *argObject);
	MessageWagon *GrabMessage(void);
	void GetQueueSize(int &aCurr_count,int &aCurr_bytes,int &aHigh_count,int &aHigh_bytes);

	sem_t					MessageSignal;

private:

	pthread_mutex_t			ListLock;
	MessageWagon			*ListHead;
	MessageWagon			*ListTail;
	int						curr_count;
	int						curr_bytes;
	int						high_count;
	int						high_bytes;
};
/*--------------------------------------------------------------------------*/
class MessageWagon
{
friend class MessageQueue;

public:

	MessageWagon(u_int8_t argCommand,u_int64_t argIndex,const void *argBuffer,int argLength);
	MessageWagon(u_int8_t argCommand,const char *argString);
	MessageWagon(u_int8_t argCommand,u_int64_t argIndex);
	MessageWagon(u_int8_t argCommand);
	virtual ~MessageWagon(void);

	u_int64_t				index;
	u_int8_t				command;
	time_t					timestamp;
	void					*buffer;
	int						length;

private:

	MessageWagon			*next;
};
/*--------------------------------------------------------------------------*/
class HashTable
{
public:

	HashTable(int aBuckets);
	virtual ~HashTable(void);

	int InsertObject(HashObject *aObject);
	int DeleteObject(HashObject *aObject);
	HashObject* SearchObject(u_int64_t aValue);

	void GetTableSize(int &aCount,int &aBytes);
	void DumpDetail(FILE *aFile);
	int PurgeStaleObjects(time_t aStamp);

private:

	u_int64_t GetHashValue(u_int64_t aValue);

	HashObject				**table;
	pthread_mutex_t			*control;
	int						buckets;
};
/*--------------------------------------------------------------------------*/
class HashObject
{
friend class HashTable;

public:

	HashObject(u_int64_t aSessionl,u_int16_t aProtocol);
	virtual ~HashObject(void);

	virtual void ResetTimeout(void);

	inline const char *GetNetString(void) { return(netstring); }
	inline u_int64_t GetNetSession(void) { return(netsession); }
	inline u_int16_t GetNetProtocol(void) { return(netprotocol); }

	virtual char *GetObjectString(char *target,int maxlen) = 0;

protected:

	virtual int GetObjectSize(void);

private:

	HashObject				*next;
	u_int16_t				netprotocol;
	u_int64_t				netsession;
	time_t					timeout;
	char					netstring[24];
};
/*--------------------------------------------------------------------------*/
class SessionObject : public HashObject
{
public:

	SessionObject(u_int64_t aSession,
		u_int8_t aProtocol,
		navl_host_t *aClient,
		navl_host_t *aServer);

	virtual ~SessionObject(void);

	void UpdateObject(const char *aApplication,
		const char * aProtochain,
		short aConfidence,
		short aState);

	void UpdateDetail(const char *aDetail);
	char *GetObjectString(char *target,int maxlen);

	inline const char *GetApplication(void)	{ return(application); }
	inline const char *GetProtochain(void)	{ return(protochain); }
	inline const char *GetDetail(void)		{ return(detail == NULL ? "" : detail); }
	inline short GetConfidence(void)		{ return(confidence); }
	inline short GetState(void)				{ return(state); }

	navl_host_t				clientinfo;
	navl_host_t				serverinfo;
	navl_conn_t				vinestat;

private:

	int GetObjectSize(void);

	short					state;
	short					confidence;
	char					*application;
	char					*protochain;
	char					*detail;
};
/*--------------------------------------------------------------------------*/
class Problem
{
public:

	inline Problem(const char *aString = NULL,int aValue = 0)
	{
	string = aString;
	value = aValue;
	}

	inline ~Problem(void)
	{
	}

	const char				*string;
	int						value;
};
/*--------------------------------------------------------------------------*/
void* classify_thread(void *arg);
void attr_callback(navl_handle_t handle,navl_conn_t conn,int attr_type,int attr_length,const void *attr_value,int attr_flag,void *arg);
int navl_callback(navl_handle_t handle,navl_result_t result,navl_state_t state,navl_conn_t conn,void *arg,int error);
void vineyard_shutdown(void);
void vineyard_debug(const char *dumpfile);
void navl_bind_externals(void);
void log_vineyard(SessionObject *session,const char *message,int direction,void *rawdata,int rawsize);
int vineyard_startup(void);
int vineyard_config(const char *key,int value);
int	vineyard_logger(const char *level,const char *func,const char *format,...);
int vineyard_printf(const char *format,...);
/*--------------------------------------------------------------------------*/
void hexmessage(int category,int priority,const void *buffer,int size);
void logmessage(int category,int priority,const char *format,...);
void sysmessage(int priority,const char *format,...);
void rawmessage(int priority,const char *message);
const char *grab_config_item(char** const filedata,const char *search,char *target,int size,const char *init);
void load_configuration(void);
void periodic_checkup(void);
void sighandler(int sigval);
void logrecycle(void);
char *itolevel(int value,char *dest);
char *nowtimestr(char *target);
char *runtimestr(char *target);
char *pad(char *target,u_int64_t value,int width = 0);
/*--------------------------------------------------------------------------*/
#ifndef DATALOC
#define DATALOC extern
#endif
/*--------------------------------------------------------------------------*/
DATALOC pthread_t			g_classify_tid;
DATALOC sem_t				g_classify_sem;
DATALOC struct itimerval	g_itimer;
DATALOC struct timeval		g_runtime;
DATALOC size_t				g_stacksize;
DATALOC NetworkServer		*g_netserver;
DATALOC MessageQueue		*g_messagequeue;
DATALOC HashTable			*g_sessiontable;
DATALOC FILE				*g_logfile;
DATALOC char				g_cfgfile[256];
DATALOC int					g_protocount;
DATALOC int					g_logrecycle;
DATALOC int					g_shutdown;
DATALOC int					g_console;
DATALOC int					g_nolimit;
DATALOC int					g_nofork;
DATALOC int					g_debug;
DATALOC char				cfg_navl_plugins[256];
DATALOC char				cfg_dump_path[256];
DATALOC char				cfg_core_path[256];
DATALOC char				cfg_log_path[256];
DATALOC char				cfg_log_file[256];
DATALOC int					cfg_facebook_subclass;
DATALOC int					cfg_skype_confidence_thresh;
DATALOC int					cfg_skype_packet_thresh;
DATALOC int					cfg_skype_probe_thresh;
DATALOC int					cfg_skype_random_thresh;
DATALOC int					cfg_skype_require_history;
DATALOC int					cfg_skype_seq_cache_time;
DATALOC int					cfg_packet_timeout;
DATALOC int					cfg_packet_maximum;
DATALOC int					cfg_hash_buckets;
DATALOC int					cfg_navl_defrag;
DATALOC int					cfg_navl_debug;
DATALOC int					cfg_mem_limit;
DATALOC int					cfg_tcp_timeout;
DATALOC int					cfg_udp_timeout;
DATALOC int					cfg_client_port;
DATALOC int					cfg_http_limit;
DATALOC int					err_notconn;
DATALOC int					err_unknown;
DATALOC int					err_nobufs;
DATALOC int					err_nomem;
DATALOC int					err_nosr;
DATALOC u_int64_t			msg_totalcount;
DATALOC u_int64_t			msg_timedrop;
DATALOC u_int64_t			msg_sizedrop;
DATALOC int					vineyard_duplicate;
DATALOC int					vineyard_garbage;
DATALOC int					client_misscount;
DATALOC int					client_hitcount;
/*--------------------------------------------------------------------------*/

