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
const unsigned int CAT_PACKET	= 0x0008;
const unsigned int CAT_SESSION	= 0x0010;
const unsigned int CAT_TRACKER	= 0x0020;

const unsigned char MSG_DEBUG		= 'D';
const unsigned char MSG_PACKET		= 'P';
const unsigned char MSG_SHUTDOWN	= 'S';
/*--------------------------------------------------------------------------*/
class NetworkServer;
class NetworkClient;
class MessageQueue;
class MessageWagon;
class SessionObject;
class TrackerObject;
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
	int						netsock;

private:

	void BuildConfiguration(void);
	void BuildDebugInfo(void);
	void BuildProtoList(void);
	void BuildHelpPage(void);
	void DumpEverything(void);
	void AdjustLogCategory(void);
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

	MessageWagon(u_int8_t argCommand,const unsigned char *argBuffer,int argLength);
	MessageWagon(u_int8_t argCommand,const char *argString);
	MessageWagon(u_int8_t argCommand);
	virtual ~MessageWagon(void);

	unsigned char			*buffer;
	u_int8_t				command;
	time_t					timestamp;
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
	HashObject* SearchObject(const char *aTitle);

	void GetTableSize(int &aCount,int &aBytes);
	void DumpDetail(FILE *aFile);
	int PurgeStaleObjects(time_t aStamp);

private:

	unsigned int GetHashValue(const char *aString);

	HashObject				**table;
	pthread_mutex_t			*control;
	int						buckets;
};
/*--------------------------------------------------------------------------*/
class HashObject
{
friend class HashTable;

public:

	HashObject(unsigned short aProto,const char *aHashname);
	virtual ~HashObject(void);

	virtual char *GetObjectString(char *target,int maxlen);
	virtual void ScheduleExpiration(void);
	virtual void ResetTimeout(void);

	inline const char *GetHashname(void)	{ return(hashname); }

protected:

	virtual int GetObjectSize(void);

private:

	HashObject				*next;
	unsigned short			netproto;
	time_t					timeout;
	char					*hashname;
};
/*--------------------------------------------------------------------------*/
class SessionObject : public HashObject
{
public:

	SessionObject(const char *aHashname,
		u_int8_t aNetProto,
		u_int32_t aClientAddr,
		u_int16_t aClientPort,
		u_int32_t aServerAddr,
		u_int16_t aServerPort);

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

	inline int IsActive(void)				{ return(upcount); }

	u_int8_t				netproto;
	u_int32_t				clientaddr;
	u_int16_t				clientport;
	u_int32_t				serveraddr;
	u_int16_t				serverport;

private:

	int GetObjectSize(void);

	short					confidence;
	short					state;
	char					*application;
	char					*protochain;
	char					*detail;
	int						upcount;
};
/*--------------------------------------------------------------------------*/
class TrackerObject : public HashObject
{
public:

	TrackerObject(unsigned short aNetwork,const char *aHashname);
	virtual ~TrackerObject(void);

	void UpdateObject(u_int32_t aSaddr,u_int16_t aSport,u_int32_t aDaddr,u_int16_t aDport);
	char *GetObjectString(char *target,int maxlen);

	inline u_int32_t GetSaddr(void)			{ return(orig_saddr); }
	inline u_int16_t GetSport(void)			{ return(orig_sport); }
	inline u_int32_t GetDaddr(void)			{ return(orig_daddr); }
	inline u_int16_t GetDport(void)			{ return(orig_dport); }

private:

	int GetObjectSize(void);

	u_int32_t				orig_saddr;
	u_int16_t				orig_sport;
	u_int32_t				orig_daddr;
	u_int16_t				orig_dport;
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
struct xphdr
{
	u_int16_t				sport;
	u_int16_t				dport;
};
/*--------------------------------------------------------------------------*/
void* netfilter_thread(void *arg);
int netq_callback(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad,void *data);
void netfilter_shutdown(void);
int netfilter_startup(void);
/*--------------------------------------------------------------------------*/
void* classify_thread(void *arg);
void attr_callback(navl_handle_t handle,navl_conn_id_t conn,int attr_type,int attr_length,const void *attr_value,int attr_flag,void *arg);
int navl_callback(navl_handle_t handle,navl_result_t result,navl_state_t state,navl_conn_id_t conn,void *arg,int error);
void process_packet(unsigned char *rawpkt,int rawlen);
void log_packet(unsigned char *rawpkt,int rawlen);
void vineyard_shutdown(void);
void vineyard_debug(const char *dumpfile);
int vineyard_startup(void);
void navl_bind_externals(void);
int vineyard_config(const char *key,int value);
int	vineyard_logger(const char *level,const char *func,const char *format,...);
int vineyard_printf(const char *format,...);
/*--------------------------------------------------------------------------*/
void* conntrack_thread(void *arg);
int conn_callback(enum nf_conntrack_msg_type type,struct nf_conntrack *ct,void *data);
void conntrack_shutdown(void);
int conntrack_startup(void);
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
DATALOC pthread_t			g_netfilter_tid;
DATALOC pthread_t			g_conntrack_tid;
DATALOC pthread_t			g_classify_tid;
DATALOC sem_t				g_netfilter_sem;
DATALOC sem_t				g_conntrack_sem;
DATALOC sem_t				g_classify_sem;
DATALOC struct itimerval	g_itimer;
DATALOC struct timeval		g_runtime;
DATALOC size_t				g_stacksize;
DATALOC NetworkServer		*g_netserver;
DATALOC MessageQueue		*g_messagequeue;
DATALOC HashTable			*g_sessiontable;
DATALOC HashTable			*g_trackertable;
DATALOC FILE				*g_logfile;
DATALOC char				g_cfgfile[256];
DATALOC char				*g_protolist;
DATALOC int					g_logrecycle;
DATALOC int					g_shutdown;
DATALOC int					g_console;
DATALOC int					g_skiptcp;
DATALOC int					g_skipudp;
DATALOC int					g_nofork;
DATALOC int					g_bypass;
DATALOC int					g_alarm;
DATALOC int					g_debug;
DATALOC char				cfg_navl_plugins[256];
DATALOC char				cfg_dump_path[256];
DATALOC char				cfg_core_path[256];
DATALOC char				cfg_log_path[256];
DATALOC char				cfg_log_file[256];
DATALOC int					cfg_facebook_subclass;
DATALOC int					cfg_skype_probe_thresh;
DATALOC int					cfg_skype_packet_thresh;
DATALOC int					cfg_skype_random_thresh;
DATALOC int					cfg_skype_require_history;
DATALOC int					cfg_packet_timeout;
DATALOC int					cfg_packet_maximum;
DATALOC int					cfg_packet_thread;
DATALOC int					cfg_hash_buckets;
DATALOC int					cfg_navl_defrag;
DATALOC int					cfg_navl_debug;
DATALOC int					cfg_mem_limit;
DATALOC int					cfg_tcp_timeout;
DATALOC int					cfg_udp_timeout;
DATALOC int					cfg_purge_delay;
DATALOC int					cfg_client_port;
DATALOC int					cfg_sock_buffer;
DATALOC int					cfg_navl_flows;
DATALOC int					cfg_http_limit;
DATALOC int					cfg_net_buffer;
DATALOC int					cfg_net_maxlen;
DATALOC int					cfg_net_queue;
DATALOC int					err_notconn;
DATALOC int					err_unknown;
DATALOC int					err_nobufs;
DATALOC int					err_nomem;
DATALOC int					err_nosr;
DATALOC u_int64_t			pkt_totalcount;
DATALOC u_int64_t			pkt_timedrop;
DATALOC u_int64_t			pkt_sizedrop;
DATALOC u_int64_t			pkt_faildrop;
DATALOC int					client_misscount;
DATALOC int					client_hitcount;
DATALOC int					tracker_unknown;
DATALOC int					tracker_error;
/*--------------------------------------------------------------------------*/

