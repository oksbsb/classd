// NETCLIENT.CPP
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
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
if ((netsock < 0) && (errno == EWOULDBLOCK)) throw(new Problem());
if (netsock < 0) throw(new Problem("Error returned from accept()",errno));

// construct network name string for logging and such
username = inet_ntoa(netaddr.sin_addr);
if (username == NULL) username = "xxx.xxx.xxx.xxx";
sprintf(netname,"%s:%d",username,netaddr.sin_port);

logmessage(CAT_CLIENT,LOG_DEBUG,"NETCLIENT CONNECT: %s\n",netname);
}
/*--------------------------------------------------------------------------*/
NetworkClient::~NetworkClient(void)
{
logmessage(CAT_CLIENT,LOG_DEBUG,"NETCLIENT GOODBYE: %s\n",netname);

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

logmessage(CAT_CLIENT,LOG_DEBUG,"NETCLIENT QUERY: %s --> %s\n",netname,querybuff);

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
StatusObject	*local;

// first check for all our special queries

	if (strcasecmp(querybuff,"DUMP") == 0)
	{
	DumpEverything();
	return(1);
	}

	if (strcasecmp(querybuff,"CONFIG") == 0)
	{
	BuildConfiguration();
	return(1);
	}

	if (strcasecmp(querybuff,"DEBUG") == 0)
	{
	BuildDebugInfo();
	return(1);
	}

	if (strcasecmp(querybuff,"PROTO") == 0)
	{
	BuildProtoList();
	return(1);
	}

	if (strcasecmp(querybuff,"MEM") == 0)
	{
	BuildMemoryStats();
	return(1);
	}

	if (strcasecmp(querybuff,"CLIENT OFF") == 0)
	{
	sysmessage(LOG_NOTICE,"Client debug logging has been disabled\n");
	replyoff = sprintf(replybuff,"%s","Client debug logging been disabled\r\n\r\n");
	g_debug&=~CAT_CLIENT;
	return(1);
	}

	if (strcasecmp(querybuff,"CLIENT ON") == 0)
	{
	sysmessage(LOG_NOTICE,"Client debug logging has been enabled\n");
	replyoff = sprintf(replybuff,"%s","Client debug logging has been enabled\r\n\r\n");
	g_debug|=CAT_CLIENT;
	return(1);
	}

	if (strcasecmp(querybuff,"FILTER OFF") == 0)
	{
	sysmessage(LOG_NOTICE,"Filter debug logging has been disabled\n");
	replyoff = sprintf(replybuff,"%s","Filter debug logging been disabled\r\n\r\n");
	g_debug&=~CAT_FILTER;
	return(1);
	}

	if (strcasecmp(querybuff,"FILTER ON") == 0)
	{
	sysmessage(LOG_NOTICE,"Filter debug logging has been enabled\n");
	replyoff = sprintf(replybuff,"%s","Filter debug logging has been enabled\r\n\r\n");
	g_debug|=CAT_FILTER;
	return(1);
	}

	if (strcasecmp(querybuff,"LOGIC OFF") == 0)
	{
	sysmessage(LOG_NOTICE,"Logic debug logging has been disabled\n");
	replyoff = sprintf(replybuff,"%s","Logic debug logging been disabled\r\n\r\n");
	g_debug&=~CAT_LOGIC;
	return(1);
	}

	if (strcasecmp(querybuff,"LOGIC ON") == 0)
	{
	sysmessage(LOG_NOTICE,"Logic debug logging has been enabled\n");
	replyoff = sprintf(replybuff,"%s","Logic debug logging has been enabled\r\n\r\n");
	g_debug|=CAT_LOGIC;
	return(1);
	}

	if (strcasecmp(querybuff,"HELP") == 0)
	{
	BuildHelpPage();
	return(1);
	}

if (strcasecmp(querybuff,"EXIT") == 0) return(0);
if (strcasecmp(querybuff,"QUIT") == 0) return(0);

// not special so use the query string to search the connection hash table
local = dynamic_cast<StatusObject*>(g_statustable->SearchObject(querybuff));

	// if we have a hit return the found result
	if ((local != NULL) && (local->IsActive() != 0))
	{
	logmessage(CAT_CLIENT,LOG_DEBUG,"NETCLIENT FOUND = %s [%s|%s|%s|%d|%d]\n",querybuff,
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

	www_hitcount++;
	}

	// otherwise return the empty result
	else
	{
	logmessage(CAT_CLIENT,LOG_DEBUG,"NETCLIENT EMPTY = %s\n",querybuff);
	replyoff = sprintf(replybuff,"EMPTY: %s\r\n",querybuff);
	www_misscount++;
	}

return(1);
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
char		temp[32];

replyoff = sprintf(replybuff,"========== CLASSD DEBUG INFO ==========\r\n");
replyoff+=sprintf(&replybuff[replyoff],"  Version: %s\r\n",VERSION);
replyoff+=sprintf(&replybuff[replyoff],"  Build: %s\r\n",BUILDID);
replyoff+=sprintf(&replybuff[replyoff],"  Web Hit Count: %s\r\n",pad(temp,www_hitcount));
replyoff+=sprintf(&replybuff[replyoff],"  Web Miss Count: %s\r\n",pad(temp,www_misscount));
replyoff+=sprintf(&replybuff[replyoff],"  Packet Counter: %s\r\n",pad(temp,pkt_totalcount));
replyoff+=sprintf(&replybuff[replyoff],"  Packet Timeout: %s\r\n",pad(temp,pkt_timedrop));
replyoff+=sprintf(&replybuff[replyoff],"  Packet Overrun: %s\r\n",pad(temp,pkt_sizedrop));
replyoff+=sprintf(&replybuff[replyoff],"  Debug Level: %04X\r\n",g_debug);
replyoff+=sprintf(&replybuff[replyoff],"  No Fork Flag: %d\r\n",g_nofork);
replyoff+=sprintf(&replybuff[replyoff],"  Console Flag: %d\r\n",g_console);
replyoff+=sprintf(&replybuff[replyoff],"  Bypass Flag %d\r\n",g_bypass);
replyoff+=sprintf(&replybuff[replyoff],"\r\n");

replyoff+=sprintf(&replybuff[replyoff],"========== VINEYARD DEBUG INFO ==========\r\n");
replyoff+=sprintf(&replybuff[replyoff],"  NO MEMORY ERRORS ......... %s\r\n",pad(temp,err_nomem));
replyoff+=sprintf(&replybuff[replyoff],"  NO FLOW ERRORS ........... %s\r\n",pad(temp,err_nobufs));
replyoff+=sprintf(&replybuff[replyoff],"  NO RESOURCES ERRORS ...... %s\r\n",pad(temp,err_nosr));
replyoff+=sprintf(&replybuff[replyoff],"  NO CONNECTION ERRORS ..... %s\r\n",pad(temp,err_notconn));
replyoff+=sprintf(&replybuff[replyoff],"  UNKNOWN ERRORS ........... %s\r\n",pad(temp,err_unknown));
replyoff+=sprintf(&replybuff[replyoff],"  CONN_INIT ERRORS ......... %s\r\n",pad(temp,err_conninit));
replyoff+=sprintf(&replybuff[replyoff],"  CONN_FINI ERRORS ......... %s\r\n",pad(temp,err_connfini));
replyoff+=sprintf(&replybuff[replyoff],"  TCP CLEANUP COUNT ........ %s\r\n",pad(temp,g_tcp_cleanup));
replyoff+=sprintf(&replybuff[replyoff],"  UDP CLEANUP COUNT ........ %s\r\n",pad(temp,g_udp_cleanup));
replyoff+=sprintf(&replybuff[replyoff],"\r\n");
}
/*--------------------------------------------------------------------------*/
void NetworkClient::BuildProtoList(void)
{
char	temp[32];
int		total;
int		x;

replyoff = sprintf(replybuff,"===== VINEYARD APPLICATION LIST =====\r\n");

// get the total number of protocols from the vineyard library
total = navl_proto_max_id();

	if (total == -1)
	{
	replyoff = sprintf(replybuff,"ERROR RETURNED FROM navl_proto_max_id()\r\n\r\n");
	return;
	}

	// get the name of each protocol and append to reply buffer
	for(x = 0;x < total;x++)
	{
	temp[0] = 0;
	navl_proto_get_name(x,temp,sizeof(temp));
	if (strlen(temp) == 0) continue;
	replyoff+=sprintf(&replybuff[replyoff],"%d = %s\r\n",x,temp);
	}

replyoff+=sprintf(&replybuff[replyoff],"\r\n");
}
/*--------------------------------------------------------------------------*/
void NetworkClient::BuildMemoryStats(void)
{
int			count,bytes,hicnt,himem;
char		temp[32];

replyoff = sprintf(replybuff,"========== CLASSD MEMORY USAGE ==========\r\n\r\n");

// get the total size of the lookup table
g_messagequeue->GetQueueSize(count,bytes,hicnt,himem);
replyoff+=sprintf(&replybuff[replyoff],"  ----- Message Queue -----\r\n");
replyoff+=sprintf(&replybuff[replyoff],"    Current Items: %s\r\n",pad(temp,count));
replyoff+=sprintf(&replybuff[replyoff],"    Current Bytes: %s\r\n",pad(temp,bytes));
replyoff+=sprintf(&replybuff[replyoff],"    Highest Items: %s\r\n",pad(temp,hicnt));
replyoff+=sprintf(&replybuff[replyoff],"    Highest Bytes: %s\r\n",pad(temp,himem));

// get the total size of the status table
g_statustable->GetTableSize(count,bytes);
replyoff+=sprintf(&replybuff[replyoff],"\r\n  ----- Session Hash Table -----\r\n");
replyoff+=sprintf(&replybuff[replyoff],"    Current Items: %s\r\n",pad(temp,count));
replyoff+=sprintf(&replybuff[replyoff],"    Current Bytes: %s\r\n",pad(temp,bytes));

// get the total size of the lookup table
g_lookuptable->GetTableSize(count,bytes);
replyoff+=sprintf(&replybuff[replyoff],"\r\n  ----- Conntrack Hash Table -----\r\n");
replyoff+=sprintf(&replybuff[replyoff],"    Current Items: %s\r\n",pad(temp,count));
replyoff+=sprintf(&replybuff[replyoff],"    Current Bytes: %s\r\n",pad(temp,bytes));

replyoff+=sprintf(&replybuff[replyoff],"\r\n");
}
/*--------------------------------------------------------------------------*/
void NetworkClient::BuildConfiguration(void)
{
replyoff = sprintf(replybuff,"========== CLASSD CONFIGURATION ==========\r\n");

replyoff+=sprintf(&replybuff[replyoff],"CLASSD_LOG_PATH ......... %s\r\n",cfg_log_path);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_LOG_FILE ......... %s\r\n",cfg_log_file);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_DUMP_PATH ........ %s\r\n",cfg_dump_path);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_PLUGIN_PATH ...... %s\r\n",cfg_navl_plugins);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_HASH_BUCKETS ..... %d\r\n",cfg_hash_buckets);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_MAX_FLOWS ........ %d\r\n",cfg_navl_flows);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_IP_DEFRAG ........ %d\r\n",cfg_navl_defrag);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_TCP_TIMEOUT ...... %d\r\n",cfg_tcp_timeout);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_UDP_TIMEOUT ...... %d\r\n",cfg_udp_timeout);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_HTTP_LIMIT ....... %d\r\n",cfg_http_limit);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_PURGE_DELAY ...... %d\r\n",cfg_purge_delay);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_CLIENT_PORT ...... %d\r\n",cfg_client_port);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_QUEUE_NUM ........ %d\r\n",cfg_net_queue);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_PACKET_THREAD .... %d\r\n",cfg_packet_thread);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_PACKET_TIMEOUT ... %d\r\n",cfg_packet_timeout);
replyoff+=sprintf(&replybuff[replyoff],"CLASSD_PACKET_MAXIMUM ... %d\r\n",cfg_packet_maximum);

replyoff+=sprintf(&replybuff[replyoff],"\r\n");
}
/*--------------------------------------------------------------------------*/
void NetworkClient::BuildHelpPage(void)
{
replyoff = sprintf(replybuff,"========== HELP PAGE ==========\r\n");

replyoff+=sprintf(&replybuff[replyoff],"CONFIG - display all daemon configuration values\r\n");
replyoff+=sprintf(&replybuff[replyoff],"DEBUG - display daemon debug information\r\n");
replyoff+=sprintf(&replybuff[replyoff],"PROTO - retrieve the list of recognized protocols\r\n");
replyoff+=sprintf(&replybuff[replyoff],"MEM - display memory usage statistics\r\n");
replyoff+=sprintf(&replybuff[replyoff],"CLIENT [ON | OFF ] - enable/disable client debug logging\r\n");
replyoff+=sprintf(&replybuff[replyoff],"FILTER [ON | OFF ] - enable/disable filter debug logging\r\n");
replyoff+=sprintf(&replybuff[replyoff],"LOGIC [ON | OFF ] - enable/disable logic debug logging\r\n");
replyoff+=sprintf(&replybuff[replyoff],"DUMP - dump low level debug information to file\r\n");
replyoff+=sprintf(&replybuff[replyoff],"HELP - display this spiffy help page\r\n");
replyoff+=sprintf(&replybuff[replyoff],"EXIT or QUIT - disconnect the session\r\n");
replyoff+=sprintf(&replybuff[replyoff],"\nAll other requests will search the connection table\r\n\r\n");
}
/*--------------------------------------------------------------------------*/
void NetworkClient::DumpEverything(void)
{
FILE		*stream;
unsigned	dumpsize;
char		dumpfile[256];
char		temp[64];

// create the dump file
sprintf(dumpfile,"%s/classd-dump.txt",cfg_dump_path);
stream = fopen(dumpfile,"a");

	if (stream == NULL)
	{
	replyoff = sprintf(replybuff,"UNABLE TO CREATE TEMPORARY FILE\r\n");
	return;
	}

// dump our build information
timestring(temp);
fprintf(stream,"===========================================================================\r\n");
fprintf(stream,"=                    Untangle CLASSd Debug Information                    =\r\n");
fprintf(stream,"===========================================================================\r\n");
fprintf(stream,"  Report Date: %s\r\n",temp);
fprintf(stream,"  Version: %s\r\n",VERSION);
fprintf(stream,"  Build: %s\r\n",BUILDID);
fprintf(stream,"  Web Hit Count: %s\r\n",pad(temp,www_hitcount));
fprintf(stream,"  Web Miss Count: %s\r\n",pad(temp,www_misscount));
fprintf(stream,"  Packet Counter: %s\r\n",pad(temp,pkt_totalcount));
fprintf(stream,"  Packet Timeout: %s\r\n",pad(temp,pkt_timedrop));
fprintf(stream,"  Packet Overrun: %s\r\n",pad(temp,pkt_sizedrop));
fprintf(stream,"  Debug Level: %04X\r\n",g_debug);
fprintf(stream,"  No Fork Flag: %d\r\n",g_nofork);
fprintf(stream,"  Console Flag: %d\r\n",g_console);
fprintf(stream,"  Bypass Flag: %d\r\n",g_bypass);
fprintf(stream,"\r\n");

// dump everything in the status hashtable
fprintf(stream,"========== CONNECTION STATUS TABLE ==========\r\n");
g_statustable->DumpDetail(stream);
fprintf(stream,"\r\n");

// dump everything in the conntrack hashtable
fprintf(stream,"========== CONNTRACK LOOKUP TABLE ==========\r\n");
g_lookuptable->DumpDetail(stream);
fprintf(stream,"\r\n");

// dump the vineyard stream error counters
fprintf(stream,"========== VINEYARD DETAIL ==========\r\n");
fprintf(stream,"  NO MEMORY ERRORS ......... %s\r\n",pad(temp,err_nomem));
fprintf(stream,"  NO FLOW ERRORS ........... %s\r\n",pad(temp,err_nobufs));
fprintf(stream,"  NO RESOURCES ERRORS ...... %s\r\n",pad(temp,err_nosr));
fprintf(stream,"  NO CONNECTION ERRORS ..... %s\r\n",pad(temp,err_notconn));
fprintf(stream,"  UNKNOWN ERRORS ........... %s\r\n",pad(temp,err_unknown));
fprintf(stream,"  CONN_INIT ERRORS ......... %s\r\n",pad(temp,err_conninit));
fprintf(stream,"  CONN_FINI ERRORS ......... %s\r\n",pad(temp,err_connfini));
fprintf(stream,"  TCP CLEANUP COUNT ........ %s\r\n",pad(temp,g_tcp_cleanup));
fprintf(stream,"  UDP CLEANUP COUNT ........ %s\r\n",pad(temp,g_udp_cleanup));
fprintf(stream,"\r\n");

// dump the vineyard diagnostic info and wrap in calls
// to fflush since we're passing the file descriptor
fflush(stream);
navl_diag(fileno(stream));
fflush(stream);
fprintf(stream,"\r\n");

// get the size of the file and read into buffer
dumpsize = ftell(stream);

// close the dump file
fclose(stream);

replyoff = sprintf(replybuff,"========== DUMP FILE CREATED ==========\r\n");
replyoff+=sprintf(&replybuff[replyoff],"FILE: %s\r\n",dumpfile);
replyoff+=sprintf(&replybuff[replyoff],"SIZE: %s\r\n\r\n",pad(temp,dumpsize));
}
/*--------------------------------------------------------------------------*/

