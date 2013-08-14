// SESSION.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2013 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
SessionObject::SessionObject(u_int64_t aSession,
	u_int8_t aProtocol,
	navl_host_t *aClient,
	navl_host_t *aServer) : HashObject(aSession,aProtocol)
{
state = 0;
confidence = 0;
application = NULL;
protochain = NULL;
detail = NULL;

vinestat = NULL;

memcpy(&clientinfo,aClient,sizeof(clientinfo));
memcpy(&serverinfo,aServer,sizeof(serverinfo));

// set the initial state that will be returned to clients while waiting
// for the classify thread to process the initial chunk of data
if (aProtocol == IPPROTO_TCP) UpdateObject("TCP","/TCP",0,NAVL_STATE_INSPECTING);
if (aProtocol == IPPROTO_UDP) UpdateObject("UDP","/UDP",0,NAVL_STATE_INSPECTING);
}
/*--------------------------------------------------------------------------*/
SessionObject::~SessionObject(void)
{
if (application != NULL) free(application);
if (protochain != NULL) free(protochain);
if (detail != NULL) free(detail);
}
/*--------------------------------------------------------------------------*/
void SessionObject::UpdateObject(const char *aApplication,
	const char *aProtochain,
	short aConfidence,
	short aState)
{
ResetTimeout();

application = (char *)realloc(application,strlen(aApplication) + 1);
strcpy(application,aApplication);

protochain = (char *)realloc(protochain,strlen(aProtochain) + 1);
strcpy(protochain,aProtochain);

confidence = aConfidence;
state = aState;
}
/*--------------------------------------------------------------------------*/
void SessionObject::UpdateDetail(const char *aDetail)
{
detail = (char *)realloc(detail,strlen(aDetail) + 1);
strcpy(detail,aDetail);
}
/*--------------------------------------------------------------------------*/
int SessionObject::GetObjectSize(void)
{
int			mysize;

mysize = HashObject::GetObjectSize();
if (application != NULL) mysize+=(strlen(application) + 1);
if (protochain != NULL) mysize+=(strlen(protochain) + 1);
if (detail != NULL) mysize+=(strlen(detail) + 1);
return(mysize);
}
/*--------------------------------------------------------------------------*/
char *SessionObject::GetObjectString(char *target,int maxlen)
{
const char		*local;

if (detail == NULL) local = "";
else local = detail;

snprintf(target,maxlen,"%s [%d|%d|%s|%s|%s]",GetNetString(),state,confidence,application,protochain,local);

return(target);
}
/*--------------------------------------------------------------------------*/

