// NETCLIENT.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2013 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
NetworkClient::NetworkClient(int aSock)
{
const char			*username;
unsigned			size;

// initialize our member variables
querybuff[0] = 0;
replybuff[0] = 0;
queryoff = 0;
replyoff = 0;
next = NULL;

// accept the inbound connection
memset(&netaddr,0,sizeof(netaddr));
size = sizeof(netaddr);
netsock = accept(aSock,(sockaddr *)&netaddr,(socklen_t *)&size);

	if (netsock < 0)
	{
	// if nobody is there just throw an empty problem
	if (errno == EWOULDBLOCK) throw(new Problem());

	// otherwise throw a problem with a message and error code
	throw(new Problem("Error returned from accept()",errno));
	}

// construct network name string for logging and such
username = inet_ntoa(netaddr.sin_addr);
if (username == NULL) username = "xxx.xxx.xxx.xxx";
sprintf(netname,"%s:%d",username,netaddr.sin_port);

LOGMESSAGE(CAT_CLIENT,LOG_DEBUG,"NETCLIENT CONNECT: %s\n",netname);
}
/*--------------------------------------------------------------------------*/
NetworkClient::~NetworkClient(void)
{
LOGMESSAGE(CAT_CLIENT,LOG_DEBUG,"NETCLIENT GOODBYE: %s\n",netname);

// shutdown and close the socket
shutdown(netsock,SHUT_RDWR);
close(netsock);
}
/*--------------------------------------------------------------------------*/
int NetworkClient::NetworkHandler(void)
{
char	*crloc,*lfloc;
int		ret;

// read data from the client to the current offset in our recv buffer
ret = recv(netsock,&querybuff[queryoff],sizeof(querybuff) - queryoff,0);

// if the client closed the connection return zero
// to let the server thread know we're done
if (ret == 0) return(0);

	// return of less than zero and we log the error
	// and let the server thread know we're done
	if (ret < 0)
	{
	sysmessage(LOG_ERR,"Error %d returned from recv(%s)\n",errno,netname);
	return(0);
	}

// add the receive count to the offset and null terminate the buffer
queryoff+=ret;
querybuff[queryoff] = 0;

// look for CR or LF characters
crloc = strchr(querybuff,'\r');
lfloc = strchr(querybuff,'\n');

// if we don't find any return one to keep session active
if ((crloc == NULL) && (lfloc == NULL)) return(1);

// wipe any CR or LF characters so they aren't included
// in the command string we received from the client
if (crloc != NULL) crloc[0] = 0;
if (lfloc != NULL) lfloc[0] = 0;

LOGMESSAGE(CAT_CLIENT,LOG_DEBUG,"NETCLIENT COMMAND: %s --> %s\n",netname,querybuff);

// handle the request
ret = ProcessRequest();
if (ret == 0) return(0);

// hande the reply
ret = TransmitReply();
if (ret == 0) return(0);

// we processed something so clear all buffers and variables
querybuff[0] = 0;
replybuff[0] = 0;
queryoff = 0;
replyoff = 0;

return(1);
}
/*--------------------------------------------------------------------------*/
int NetworkClient::ProcessRequest(void)
{
SessionObject		*local;
u_int64_t			hashcode;

// first check for all our special queries
if (strcasecmp(querybuff,"CONFIG") == 0)	{ BuildConfiguration(); return(1); }
if (strcasecmp(querybuff,"DEBUG") == 0)		{ BuildDebugInfo(); return(1); }
if (strcasecmp(querybuff,"PROTO") == 0)		{ BuildProtoList(); return(1); }
if (strcasecmp(querybuff,"HELP") == 0)		{ BuildHelpPage(); return(1); }
if (strcasecmp(querybuff,"DUMP") == 0)		{ DumpEverything(); return(1); }
if (strcasecmp(querybuff,"EXIT") == 0)		{ return(0); }
if (strcasecmp(querybuff,"QUIT") == 0) 		{ return(0); }

	// stuff that starts with plus or minus is for log control
	if ((querybuff[0] == '+') || (querybuff[0] == '-'))
	{
	AdjustLogCategory();
	return(1);
	}

	if (strncasecmp(querybuff,"CREATE:",7) == 0)
	{
	HandleCreate();
	return(1);
	}

	if (strncasecmp(querybuff,"REMOVE:",7) == 0)
	{
	HandleRemove();
	return(1);
	}

hashcode = 0;

// client and server data will be passed to the classify message queue
if (strncasecmp(querybuff,"CLIENT:",7) == 0) hashcode = HandleClient();
if (strncasecmp(querybuff,"SERVER:",7) == 0) hashcode = HandleServer();

// if we don't have a hashcode yet then this is probably a console query
if (hashcode == 0) hashcode = ExtractNetworkSession(querybuff);

	// if still zero we have no idea what is going on so just return
	if (hashcode == 0)
	{
	replyoff = sprintf(replybuff,"%s","Invalid command or query\r\n\r\n");
	return(1);
	}

local = dynamic_cast<SessionObject*>(g_sessiontable->SearchObject(hashcode));

	// if we have a hit return the found result
	if (local != NULL)
	{
	LOGMESSAGE(CAT_CLIENT,LOG_DEBUG,"NETCLIENT FOUND = %s [%s|%s|%s|%d|%d]\n",querybuff,
		local->GetApplication(),
		local->GetProtochain(),
		local->GetDetail(),
		local->GetConfidence(),
		local->GetState());

	replyoff = 0;
	replyoff+=sprintf(&replybuff[replyoff],"FOUND: %s\r\n",querybuff);
	replyoff+=sprintf(&replybuff[replyoff],"APPLICATION: %s\r\n",local->GetApplication());
	replyoff+=sprintf(&replybuff[replyoff],"PROTOCHAIN: %s\r\n",local->GetProtochain());
	replyoff+=sprintf(&replybuff[replyoff],"DETAIL: %s\r\n",local->GetDetail());
	replyoff+=sprintf(&replybuff[replyoff],"CONFIDENCE: %d\r\n",local->GetConfidence());
	replyoff+=sprintf(&replybuff[replyoff],"STATE: %d\r\n",local->GetState());

	client_hitcount++;
	}

	// otherwise return the empty result
	else
	{
	LOGMESSAGE(CAT_CLIENT,LOG_DEBUG,"NETCLIENT EMPTY = %s\n",querybuff);
	replyoff = sprintf(replybuff,"EMPTY: %s\r\n",querybuff);
	client_misscount++;
	}

return(1);
}
/*--------------------------------------------------------------------------*/
void NetworkClient::AdjustLogCategory(void)
{
int		found = 0;

	if (strcasecmp(querybuff,"-LOGIC") == 0)
	{
	sysmessage(LOG_NOTICE,"Logic debug logging has been disabled\n");
	replyoff = sprintf(replybuff,"%s","Logic debug logging been disabled\r\n\r\n");
	g_debug&=~CAT_LOGIC;
	found++;
	}

	if (strcasecmp(querybuff,"+LOGIC") == 0)
	{
	sysmessage(LOG_NOTICE,"Logic debug logging has been enabled\n");
	replyoff = sprintf(replybuff,"%s","Logic debug logging has been enabled\r\n\r\n");
	g_debug|=CAT_LOGIC;
	found++;
	}

	if (strcasecmp(querybuff,"-CLIENT") == 0)
	{
	sysmessage(LOG_NOTICE,"Client debug logging has been disabled\n");
	replyoff = sprintf(replybuff,"%s","Client debug logging been disabled\r\n\r\n");
	g_debug&=~CAT_CLIENT;
	found++;
	}

	if (strcasecmp(querybuff,"+CLIENT") == 0)
	{
	sysmessage(LOG_NOTICE,"Client debug logging has been enabled\n");
	replyoff = sprintf(replybuff,"%s","Client debug logging has been enabled\r\n\r\n");
	g_debug|=CAT_CLIENT;
	found++;
	}

	if (strcasecmp(querybuff,"-UPDATE") == 0)
	{
	sysmessage(LOG_NOTICE,"Update debug logging has been disabled\n");
	replyoff = sprintf(replybuff,"%s","Update debug logging been disabled\r\n\r\n");
	g_debug&=~CAT_UPDATE;
	found++;
	}

	if (strcasecmp(querybuff,"+UPDATE") == 0)
	{
	sysmessage(LOG_NOTICE,"Update debug logging has been enabled\n");
	replyoff = sprintf(replybuff,"%s","Update debug logging has been enabled\r\n\r\n");
	g_debug|=CAT_UPDATE;
	found++;
	}

	if (strcasecmp(querybuff,"-PACKET") == 0)
	{
	sysmessage(LOG_NOTICE,"Packet debug logging has been disabled\n");
	replyoff = sprintf(replybuff,"%s","Packet debug logging been disabled\r\n\r\n");
	g_debug&=~CAT_PACKET;
	found++;
	}

	if (strcasecmp(querybuff,"+PACKET") == 0)
	{
	sysmessage(LOG_NOTICE,"Packet debug logging has been enabled\n");
	replyoff = sprintf(replybuff,"%s","Packet debug logging has been enabled\r\n\r\n");
	g_debug|=CAT_PACKET;
	found++;
	}

	if (strcasecmp(querybuff,"-SESSION") == 0)
	{
	sysmessage(LOG_NOTICE,"Session debug logging has been disabled\n");
	replyoff = sprintf(replybuff,"%s","Session debug logging been disabled\r\n\r\n");
	g_debug&=~CAT_SESSION;
	found++;
	}

	if (strcasecmp(querybuff,"+SESSION") == 0)
	{
	sysmessage(LOG_NOTICE,"Session debug logging has been enabled\n");
	replyoff = sprintf(replybuff,"%s","Session debug logging has been enabled\r\n\r\n");
	g_debug|=CAT_SESSION;
	found++;
	}

if (found != 0) return;
replyoff = sprintf(replybuff,"%s","Unrecognized log control command\r\n\r\n");
}
/*--------------------------------------------------------------------------*/
void NetworkClient::HandleCreate(void)
{
SessionObject		*session;
char				*aa,*bb,*cc,*dd,*ee,*ff;
navl_host_t			client,server;
u_int64_t			hashcode;
u_int8_t			protocol;

// first we extract the connection details from the message

aa = strchr(querybuff,':');		// points to session id
if (aa == NULL) return;
*aa++=0;

bb = strchr(aa,':');			// points to protocol
if (bb == NULL) return;
*bb++=0;

cc = strchr(bb,':');			// points to client address
if (cc == NULL) return;
*cc++=0;

dd = strchr(cc,':');			// points to client port
if (dd == NULL) return;
*dd++=0;

ee = strchr(dd,':');			// points to server address
if (ee == NULL) return;
*ee++=0;

ff = strchr(ee,':');			// points to server port
if (ff == NULL) return;
*ff++=0;

// get the session id value and set the protocol
hashcode = ExtractNetworkSession(aa);
protocol = 0;
if (strcmp(bb,"TCP") == 0) protocol = IPPROTO_TCP;
if (strcmp(bb,"UDP") == 0) protocol = IPPROTO_UDP;

// fill the client structure
client.family = NAVL_AF_INET;
inet_aton(cc,(in_addr *)&client.in4_addr);
client.port = strtol(dd,NULL,10);

// fill the server structure
server.family = NAVL_AF_INET;
inet_aton(ee,(in_addr *)&server.in4_addr);
server.port = strtol(ff,NULL,10);

// insert the new session object in the hashtable
session = new SessionObject(hashcode,protocol,client,server);
g_sessiontable->InsertObject(session);

// post the create message to the classify thread
g_messagequeue->PushMessage(new MessageWagon(MSG_CREATE,hashcode));

// have to return something even though the node currently does not use it
replyoff = sprintf(replybuff,"CREATED: %"PRI64u"\r\n",hashcode);
}
/*--------------------------------------------------------------------------*/
void NetworkClient::HandleRemove(void)
{
u_int64_t	hashcode;
char		*aa;

aa = strchr(querybuff,':');		// points to session id
if (aa == NULL) return;
*aa++=0;
hashcode = ExtractNetworkSession(aa);

// post the remove message to the classify thread
g_messagequeue->PushMessage(new MessageWagon(MSG_REMOVE,hashcode));

// have to return something even though the node currently does not use it
replyoff = sprintf(replybuff,"REMOVED: %"PRI64u"\r\n",hashcode);
}
/*--------------------------------------------------------------------------*/
u_int64_t NetworkClient::HandleClient(void)
{
u_int64_t	hashcode;
char		*aa,*bb;
long		length,ret;

aa = strchr(querybuff,':');		// points to session id
if (aa == NULL) return(0);
*aa++=0;

bb = strchr(aa,':');			// points to data length
if (bb == NULL) return(0);
*bb++=0;

hashcode = ExtractNetworkSession(aa);
length = strtol(bb,NULL,10);

// read data from the client into the reply buffer since it is larger
ret = recv(netsock,replybuff,length,0);

	// TODO - maybe we need to try multiple times
	if (ret != length)
	{
	sysmessage(LOG_WARNING,"Only received %d of %d client bytes from %s\n",ret,length,netname);
	}

// push the data into the classify queue
g_messagequeue->PushMessage(new MessageWagon(MSG_CLIENT,hashcode,replybuff,ret));

return(hashcode);
}
/*--------------------------------------------------------------------------*/
u_int64_t NetworkClient::HandleServer(void)
{
u_int64_t			hashcode;
char				*aa,*bb;
int					length,ret;

aa = strchr(querybuff,':');		// points to session id
if (aa == NULL) return(0);
*aa++=0;

bb = strchr(aa,':');			// points to data length
if (bb == NULL) return(0);
*bb++=0;

hashcode = ExtractNetworkSession(aa);
length = strtol(bb,NULL,10);

// read data from the client into the reply buffer since it is larger
ret = recv(netsock,replybuff,length,0);

	// TODO - maybe we need to try multiple times
	if (ret != length)
	{
	sysmessage(LOG_WARNING,"Only received %d of %d server bytes from %s\n",ret,length,netname);
	}

// push the data into the classify queue
g_messagequeue->PushMessage(new MessageWagon(MSG_SERVER,hashcode,replybuff,ret));

return(hashcode);
}
/*--------------------------------------------------------------------------*/
u_int64_t NetworkClient::ExtractNetworkSession(const char *buffer)
{
u_int64_t		hashcode;

#if __WORDSIZE == 64
hashcode = strtoul(buffer,NULL,10);
#else
hashcode = strtoull(buffer,NULL,10);
#endif

return(hashcode);
}
/*--------------------------------------------------------------------------*/
int NetworkClient::TransmitReply(void)
{
struct timeval	tv;
fd_set			tester;
int				offset,ret;

offset = 0;

	while (offset != replyoff)
	{
	// clear our set and add the client socket
	FD_ZERO(&tester);
	FD_SET(netsock,&tester);

	// wait for the socket to be write ready
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret = select(netsock+1,NULL,&tester,NULL,&tv);
	if (ret < 1) continue;
	if (FD_ISSET(netsock,&tester) == 0) continue;

	// write to the socket
	ret = send(netsock,&replybuff[offset],replyoff - offset,0);

		// check for errors
		if (ret == -1)
		{
		if (errno == EWOULDBLOCK) continue;
		sysmessage(LOG_ERR,"Error %d returned from send(%s)\n",errno,netname);
		return(0);
		}

	// add the size just sent to the total transmitted
	offset+=ret;
	}

return(1);
}
/*--------------------------------------------------------------------------*/
void NetworkClient::BuildDebugInfo(void)
{
char		temp[64];
int			count,bytes,hicnt,himem;

replyoff = sprintf(replybuff,"========== CLASSD DEBUG INFO ==========\r\n");
replyoff+=sprintf(&replybuff[replyoff],"  Current Time .................... %s\r\n",nowtimestr(temp));
replyoff+=sprintf(&replybuff[replyoff],"  Run Time ........................ %s\r\n",runtimestr(temp));
replyoff+=sprintf(&replybuff[replyoff],"  Version ......................... %s\r\n",VERSION);
replyoff+=sprintf(&replybuff[replyoff],"  Build ........................... %s\r\n",BUILDID);
replyoff+=sprintf(&replybuff[replyoff],"  Architecture .................... %d Bit\r\n",(int)sizeof(void*)*8);
replyoff+=sprintf(&replybuff[replyoff],"  Debug Level ..................... 0x%04X\r\n",g_debug);
replyoff+=sprintf(&replybuff[replyoff],"  No Fork Flag .................... %d\r\n",g_nofork);
replyoff+=sprintf(&replybuff[replyoff],"  Console Flag .................... %d\r\n",g_console);
replyoff+=sprintf(&replybuff[replyoff],"  Client Hit Count ................ %s\r\n",pad(temp,client_hitcount));
replyoff+=sprintf(&replybuff[replyoff],"  Client Miss Count ............... %s\r\n",pad(temp,client_misscount));
replyoff+=sprintf(&replybuff[replyoff],"  Network Packet Counter .......... %s\r\n",pad(temp,pkt_totalcount));
replyoff+=sprintf(&replybuff[replyoff],"  Network Packet Timeout .......... %s\r\n",pad(temp,pkt_timedrop));
replyoff+=sprintf(&replybuff[replyoff],"  Network Packet Overrun .......... %s\r\n",pad(temp,pkt_sizedrop));

// get the details for the message queue
g_messagequeue->GetQueueSize(count,bytes,hicnt,himem);
replyoff+=sprintf(&replybuff[replyoff],"  Message Queue Current Count ..... %s\r\n",pad(temp,count));
replyoff+=sprintf(&replybuff[replyoff],"  Message Queue Current Bytes ..... %s\r\n",pad(temp,bytes));
replyoff+=sprintf(&replybuff[replyoff],"  Message Queue Highest Count ..... %s\r\n",pad(temp,hicnt));
replyoff+=sprintf(&replybuff[replyoff],"  Message Queue Highest Bytes ..... %s\r\n",pad(temp,himem));

// get the total size of the session table
g_sessiontable->GetTableSize(count,bytes);
replyoff+=sprintf(&replybuff[replyoff],"  Session Hash Table Items ........ %s\r\n",pad(temp,count));
replyoff+=sprintf(&replybuff[replyoff],"  Session Hash Table Bytes ........ %s\r\n",pad(temp,bytes));

replyoff+=sprintf(&replybuff[replyoff],"  Vineyard NO MEMORY Errors ....... %s\r\n",pad(temp,err_nomem));
replyoff+=sprintf(&replybuff[replyoff],"  Vineyard NO FLOW Errors ......... %s\r\n",pad(temp,err_nobufs));
replyoff+=sprintf(&replybuff[replyoff],"  Vineyard NO RESOURCE Errors ..... %s\r\n",pad(temp,err_nosr));
replyoff+=sprintf(&replybuff[replyoff],"  Vineyard NO CONNECTION Errors ... %s\r\n",pad(temp,err_notconn));
replyoff+=sprintf(&replybuff[replyoff],"  Vineyard UNKNOWN Errors ......... %s\r\n",pad(temp,err_unknown));

replyoff+=sprintf(&replybuff[replyoff],"  Vineyard Duplicate Iterator ..... %s\r\n",pad(temp,vineyard_duplicate));

replyoff+=sprintf(&replybuff[replyoff],"\r\n");
}
/*--------------------------------------------------------------------------*/
void NetworkClient::BuildProtoList(void)
{
char	temp[64];
int		x;

replyoff = sprintf(replybuff,"===== VINEYARD APPLICATION LIST =====\r\n");

	for(x = 0;x < g_protocount;x++)
	{
	replyoff+=sprintf(&replybuff[replyoff],"%-10s %s\r\n",g_protostats[x]->protocol_name,pad(temp,g_protostats[x]->packet_count));
	}
}
/*--------------------------------------------------------------------------*/
void NetworkClient::BuildConfiguration(void)
{
replyoff = sprintf(replybuff,"========== CLASSD CONFIGURATION ==========\r\n");

replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_LOG_PATH ................ %s\r\n",cfg_log_path);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_LOG_FILE ................ %s\r\n",cfg_log_file);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_DUMP_PATH ............... %s\r\n",cfg_dump_path);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_CORE_PATH ............... %s\r\n",cfg_core_path);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_PLUGIN_PATH ............. %s\r\n",cfg_navl_plugins);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_LIBRARY_DEBUG ........... %d\r\n",cfg_navl_debug);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_MEMORY_LIMIT ............ %d\r\n",cfg_mem_limit);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_HASH_BUCKETS ............ %d\r\n",cfg_hash_buckets);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_IP_DEFRAG ............... %d\r\n",cfg_navl_defrag);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_TCP_TIMEOUT ............. %d\r\n",cfg_tcp_timeout);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_UDP_TIMEOUT ............. %d\r\n",cfg_udp_timeout);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_HTTP_LIMIT .............. %d\r\n",cfg_http_limit);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_CLIENT_PORT ............. %d\r\n",cfg_client_port);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_PACKET_TIMEOUT .......... %d\r\n",cfg_packet_timeout);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_PACKET_MAXIMUM .......... %d\r\n",cfg_packet_maximum);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_FACEBOOK_SUBCLASS ....... %d\r\n",cfg_facebook_subclass);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_SKYPE_PROBE_THRESH ...... %d\r\n",cfg_skype_probe_thresh);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_SKYPE_PACKET_THRESH ..... %d\r\n",cfg_skype_packet_thresh);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_SKYPE_RANDOM_THRESH ..... %d\r\n",cfg_skype_random_thresh);
replyoff+=sprintf(&replybuff[replyoff],"  CLASSD_SKYPE_REQUIRE_HISTORY ... %d\r\n",cfg_skype_require_history);

replyoff+=sprintf(&replybuff[replyoff],"\r\n");
}
/*--------------------------------------------------------------------------*/
void NetworkClient::BuildHelpPage(void)
{
replyoff = sprintf(replybuff,"========== HELP PAGE ==========\r\n");

replyoff+=sprintf(&replybuff[replyoff],"CONFIG = display all daemon configuration values\r\n");
replyoff+=sprintf(&replybuff[replyoff],"DEBUG = display daemon debug information\r\n");
replyoff+=sprintf(&replybuff[replyoff],"PROTO = display list of recognized protocols\r\n");
replyoff+=sprintf(&replybuff[replyoff],"+LOGIC | -LOGIC = enable/disable logic debug logging\r\n");
replyoff+=sprintf(&replybuff[replyoff],"+CLIENT | -CLIENT = enable/disable netclient request logging\r\n");
replyoff+=sprintf(&replybuff[replyoff],"+UPDATE | -UPDATE = enable/disable classify status logging\r\n");
replyoff+=sprintf(&replybuff[replyoff],"+PACKET | -PACKET = enable/disable network packet logging\r\n");
replyoff+=sprintf(&replybuff[replyoff],"+SESSION | -SESSION = enable/disable netfilter session table logging\r\n");
replyoff+=sprintf(&replybuff[replyoff],"DUMP = dump low level debug information to file\r\n");
replyoff+=sprintf(&replybuff[replyoff],"HELP = display this spiffy help page\r\n");
replyoff+=sprintf(&replybuff[replyoff],"EXIT or QUIT = disconnect the session\r\n");
replyoff+=sprintf(&replybuff[replyoff],"\nAll other requests will search the connection table\r\n\r\n");
}
/*--------------------------------------------------------------------------*/
void NetworkClient::DumpEverything(void)
{
FILE	*stream;
char	dumpfile[256];

// create the dump file
sprintf(dumpfile,"%s/classd-dump.txt",cfg_dump_path);
stream = fopen(dumpfile,"a");

	if (stream == NULL)
	{
	replyoff = sprintf(replybuff,"UNABLE TO CREATE TEMPORARY FILE\r\n");
	return;
	}

fputs("##############################################################################\r\n",stream);

// dump the debug information
BuildDebugInfo();
fputs(replybuff,stream);

// dump the daemon configuration
BuildConfiguration();
fputs(replybuff,stream);

// dump everything in the session hash table
fprintf(stream,"========== CLASSD SESSION HASH TABLE ==========\r\n");
g_sessiontable->DumpDetail(stream);
fprintf(stream,"\r\n");

// flush and close the dump file
fflush(stream);
fclose(stream);

// tell the classify thread to dump the vineyard debug info
g_messagequeue->PushMessage(new MessageWagon(MSG_DEBUG,dumpfile));

replyoff = sprintf(replybuff,"========== DUMP FILE CREATED ==========\r\n");
replyoff+=sprintf(&replybuff[replyoff],"  FILE: %s\r\n",dumpfile);
}
/*--------------------------------------------------------------------------*/

