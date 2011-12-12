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
char	*find;
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
	logmessage(LOG_ERR,"Error %d returned from recv(%s)\n",errno,netname);
	return(0);
	}

// add the receive count to the offet and null terminate the buffer
queryoff+=ret;
querybuff[queryoff] = 0;

find = strstr(querybuff,"\r\n");

	// look for and proccess complete command
	if (find != NULL)
	{
	find[0] = 0;
	logmessage(CAT_CLIENT,LOG_DEBUG,"NETCLIENT QUERY: %s --> %s\n",netname,querybuff);

	ret = ProcessRequest();
	if (ret == 0) return(0);

	ret = TransmitReply();
	if (ret == 0) return(0);

	querybuff[0] = 0;
	replybuff[0] = 0;
	queryoff = 0;
	replyoff = 0;
	}

return(1);
}
/*--------------------------------------------------------------------------*/
int NetworkClient::ProcessRequest(void)
{
StatusObject	*local;

// first check for all our special queries

	if (strcasecmp(querybuff,"DEBUGINFO") == 0)
	{
	BuildDebugInfo();
	return(1);
	}

	if (strcasecmp(querybuff,"PROTOLIST") == 0)
	{
	BuildProtoList();
	return(1);
	}

	if (strcasecmp(querybuff,"HASHSTATS") == 0)
	{
	BuildHashStats();
	return(1);
	}

	if (strcasecmp(querybuff,"DEBUGCLIENT OFF") == 0)
	{
	logmessage(LOG_NOTICE,"Client debug logging has been disabled\n");
	replyoff = sprintf(replybuff,"%s","Client debug logging been disabled\r\n");
	g_debug&=~CAT_CLIENT;
	return(1);
	}

	if (strcasecmp(querybuff,"DEBUGCLIENT ON") == 0)
	{
	logmessage(LOG_NOTICE,"Client debug logging has been enabled\n");
	replyoff = sprintf(replybuff,"%s","Client debug logging has been enabled\r\n");
	g_debug|=CAT_CLIENT;
	return(1);
	}

	if (strcasecmp(querybuff,"DEBUGFILTER OFF") == 0)
	{
	logmessage(LOG_NOTICE,"Filter debug logging has been disabled\n");
	replyoff = sprintf(replybuff,"%s","Filter debug logging been disabled\r\n");
	g_debug&=~CAT_FILTER;
	return(1);
	}

	if (strcasecmp(querybuff,"DEBUGFILTER ON") == 0)
	{
	logmessage(LOG_NOTICE,"Filter debug logging has been enabled\n");
	replyoff = sprintf(replybuff,"%s","Filter debug logging has been enabled\r\n");
	g_debug|=CAT_FILTER;
	return(1);
	}

	if (strcasecmp(querybuff,"DEBUGLOGIC OFF") == 0)
	{
	logmessage(LOG_NOTICE,"Logic debug logging has been disabled\n");
	replyoff = sprintf(replybuff,"%s","Logic debug logging been disabled\r\n");
	g_debug&=~CAT_LOGIC;
	return(1);
	}

	if (strcasecmp(querybuff,"DEBUGLOGIC ON") == 0)
	{
	logmessage(LOG_NOTICE,"Logic debug logging has been enabled\n");
	replyoff = sprintf(replybuff,"%s","Logic debug logging has been enabled\r\n");
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
		logmessage(LOG_ERR,"Error %d returned from send(%s)\n",errno,netname);
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
FILE		*stream;
char		tempfile[256];
char		work[64];
int			direct;

// create a temporary file
sprintf(tempfile,"%s/classd-XXXXXX",cfg_temp_path);
direct = mkstemp(tempfile);
stream = fdopen(direct,"r+");

	if (stream == NULL)
	{
	replyoff = sprintf(replybuff,"UNABLE TO CREATE TEMPORARY FILE\n\n");
	return;
	}

// dump our build information
timestring(work);
fprintf(stream,"========== Untangle CLASSd Debug Information ==========\n");
fprintf(stream,"  Version: %s\n",VERSION);
fprintf(stream,"  Build: %s\n",BUILDID);
fprintf(stream,"  Report Date: %s\n",work);
fprintf(stream,"  Web Hit Count: %d\n",www_hitcount);
fprintf(stream,"  Web Miss Count: %d\n",www_misscount);
fprintf(stream,"\n");

// dump everything in the status hashtable
fprintf(stream,"========== CONNECTION STATUS TABLE ==========\n");
g_statustable->DumpDetail(stream);
fprintf(stream,"\n");

// dump everything in the status hashtable
fprintf(stream,"========== CONNTRACK LOOKUP TABLE ==========\n");
g_lookuptable->DumpDetail(stream);
fprintf(stream,"\n");

// dump the vineyard stream error counters
fprintf(stream,"========== VINEYARD DETAIL ==========\n");
fprintf(stream,"  NO MEMORY ERRORS ......... %d\n",err_nomem);
fprintf(stream,"  NO FLOW ERRORS ........... %d\n",err_nobufs);
fprintf(stream,"  NO RESOURCES ERRORS ...... %d\n",err_nosr);
fprintf(stream,"  NO CONNECTION ERRORS ..... %d\n",err_notconn);
fprintf(stream,"  UNKNOWN ERRORS ........... %d\n",err_unknown);
fprintf(stream,"  TCP CLEANUP COUNT ........ %d\n",g_tcp_cleanup);
fprintf(stream,"  UDP CLEANUP COUNT ........ %d\n",g_udp_cleanup);
fprintf(stream,"\n");
fflush(stream);

// dump the vineyard diagnostic info
navl_diag(fileno(stream));

// get the size of the file and read into buffer
replyoff = ftell(stream);
rewind(stream);
fread(replybuff,replyoff,1,stream);

// close and remove the temporary file
fclose(stream);
unlink(tempfile);
}
/*--------------------------------------------------------------------------*/
void NetworkClient::BuildProtoList(void)
{
char	work[32];
int		total;
int		x;

replyoff = sprintf(replybuff,"===== VINEYARD APPLICATION LIST=====\n");

// get the total number of protocols from the vineyard library
total = navl_proto_max_id();

	if (total == -1)
	{
	replyoff = sprintf(replybuff,"ERROR RETURNED FROM navl_proto_max_id()\n\n");
	return;
	}

	// get the name of each protocol and append to reply buffer
	for(x = 0;x < total;x++)
	{
	work[0] = 0;
	navl_proto_get_name(x,work,sizeof(work));
	if (strlen(work) == 0) continue;
	replyoff+=sprintf(&replybuff[replyoff],"%d = %s\n",x,work);
	}
}
/*--------------------------------------------------------------------------*/
void NetworkClient::BuildHashStats(void)
{
int		count,bytes;

// get the total size of the hash table
g_statustable->GetTableSize(count,bytes);
replyoff = sprintf(replybuff,"HASHTABLE COUNT=%d  SIZE=%d\n\n",count,bytes);
}
/*--------------------------------------------------------------------------*/
void NetworkClient::BuildHelpPage(void)
{
replyoff = sprintf(replybuff,"========== Untangle CLASSd Help Page ==========\n");

replyoff+=sprintf(&replybuff[replyoff],"HASHSTATS - display session hash table statistics\n");
replyoff+=sprintf(&replybuff[replyoff],"DEBUGINFO - dump low level debug information\n");
replyoff+=sprintf(&replybuff[replyoff],"PROTOLIST - retrieve the list of recognized protocols\n");
replyoff+=sprintf(&replybuff[replyoff],"CLIENTDEBUG [OFF | ON ] - disable/enable client debug logging\n");
replyoff+=sprintf(&replybuff[replyoff],"FILTERDEBUG [OFF | ON ] - disable/enable filter debug logging\n");
replyoff+=sprintf(&replybuff[replyoff],"LOGICDEBUG [OFF | ON ] - disable/enable logic debug logging\n");
replyoff+=sprintf(&replybuff[replyoff],"HELP - display this spiffy help page\n");
replyoff+=sprintf(&replybuff[replyoff],"EXIT or QUIT - disconnect the session\n");
replyoff+=sprintf(&replybuff[replyoff],"\nAll other requests will search the connection table\n\n");
}
/*--------------------------------------------------------------------------*/

