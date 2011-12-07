// CLASSD.H
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#ifndef VERSION
#define VERSION "TEST"
#endif

#ifndef BUILDID
#define BUILDID "0"
#endif

/*--------------------------------------------------------------------------*/
class NetworkServer;
class NetworkClient;
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

	void BuildDebugInfo(void);
	void BuildProtoList(void);
	void BuildHashStats(void);
	void BuildHelpPage(void);
	int ProcessRequest(void);
	int TransmitReply(void);
};
/*--------------------------------------------------------------------------*/
class HashTable
{
public:

	HashTable(int aBuckets);
	virtual ~HashTable(void);

	int InsertObject(HashObject *aObject);
	int DeleteObject(const char *aTitle);
	HashObject* SearchObject(const char *aTitle);

	void GetTableSize(int &aCount,int &aBytes);
	void DumpDetail(FILE *aFile);
	int PurgeStaleObjects(time_t aStamp);

private:

	unsigned int GetHashValue(const void *aString);

	HashObject				**table;
	sem_t					*control;
	int						buckets;
};
/*--------------------------------------------------------------------------*/
class HashObject
{
friend class HashTable;

public:

	HashObject(unsigned short aNetwork,
		const char *aHashname,
		const char *aApplication,
		const char *aProtochain,
		const char *aDetail,
		short aConfidence,
		short aState);

	virtual ~HashObject(void);

	void UpdateObject(const char *aApplication,
		const char * aProtochain,
		const char *aDetail,
		short aConfidence,
		short aState);

	void GetObjectString(char *target,int maxlen);

	inline const char *GetHashname(void)	{ return(hashname); }
	inline const char *GetApplication(void)	{ return(application); }
	inline const char *GetProtochain(void)	{ return(protochain); }
	inline const char *GetDetail(void)		{ return(detail); }
	inline short GetConfidence(void)		{ return(confidence); }
	inline short GetState(void)				{ return(state); }

private:

	int GetObjectSize(void);

	unsigned short			network;
	time_t					timestamp;
	char					*hashname;
	char					*application;
	char					*protochain;
	char					*detail;
	short					confidence;
	short					state;

	HashObject				*next;
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
struct callback_info
{
	struct nfq_q_handle		*handle;
	struct nfq_data			*data;
};
/*--------------------------------------------------------------------------*/
void logmessage(int priority,const char *format,...);
void logproblem(Problem *aProblem);
void load_configuration(void);
void* netfilter_thread(void *arg);
void sighandler(int sigval);
void timestring(char *target);
void recycle(void);
char *itolevel(int value,char *dest);
/*--------------------------------------------------------------------------*/
#ifndef DATALOC
#define DATALOC extern
#endif
/*--------------------------------------------------------------------------*/
DATALOC pthread_t			g_netfilter_tid;
DATALOC struct itimerval	g_itimer;
DATALOC struct timeval		g_runtime;
DATALOC NetworkServer		*g_netserver;
DATALOC HashTable			*g_conntable;
DATALOC FILE				*g_logfile;
DATALOC char				g_cfgfile[256];
DATALOC int					g_tcp_cleanup;
DATALOC int					g_udp_cleanup;
DATALOC int					g_shutdown;
DATALOC int					g_recycle;
DATALOC int					g_console;
DATALOC int					g_nofork;
DATALOC int					g_debug;
DATALOC char				cfg_navl_plugins[256];
DATALOC char				cfg_temp_path[256];
DATALOC char				cfg_log_path[256];
DATALOC char				cfg_log_file[256];
DATALOC int					cfg_navl_flows;
DATALOC int					cfg_navl_defrag;
DATALOC int					cfg_hash_buckets;
DATALOC int					cfg_tcp_timeout;
DATALOC int					cfg_udp_timeout;
DATALOC int					cfg_share_port;
DATALOC int					cfg_net_queue;
DATALOC int					err_notconn;
DATALOC int					err_unknown;
DATALOC int					err_nobufs;
DATALOC int					err_nomem;
DATALOC int					err_nosr;
DATALOC int					www_misscount;
DATALOC int					www_hitcount;
/*--------------------------------------------------------------------------*/

