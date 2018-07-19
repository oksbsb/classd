// SESSION.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2018 Untangle, Inc.
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

application_str[0][0] = 0;
application_str[1][0] = 0;
application_idx = 0;

protochain_str[0][0] = 0;
protochain_str[1][0] = 0;
protochain_idx = 0;

detail_str[0][0] = 0;
detail_str[1][0] = 0;
detail_idx = 0;

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
}
/*--------------------------------------------------------------------------*/
void SessionObject::UpdateObject(const char *aApplication,
	const char *aProtochain,
	short aConfidence,
	short aState)
{
int		anext,pnext;
int		len;

ResetTimeout();

anext = (application_idx ^ 1);
pnext = (protochain_idx ^ 1);

// copy the updated application to the inactive buffer and toggle the index
len = strlen(aApplication);
if (len >= (int)sizeof(application_str[anext])) len = (sizeof(application_str[anext]) - 1);
memcpy(application_str[anext],aApplication,len);
application_str[anext][len] = 0;
application_idx ^= 1;

// copy the updated protochain to the inactive buffer and toggle the index
len = strlen(aProtochain);
if (len >= (int)sizeof(protochain_str[pnext])) len = (sizeof(protochain_str[pnext]) - 1);
memcpy(protochain_str[pnext],aProtochain,len);
protochain_str[pnext][len] = 0;
protochain_idx ^= 1;

confidence = aConfidence;
state = aState;
}
/*--------------------------------------------------------------------------*/
void SessionObject::UpdateDetail(const char *aDetail)
{
int		dnext;
int		len;

ResetTimeout();

dnext = (detail_idx ^ 1);

// copy the updated detail to the inactive buffer and toggle the index
len = strlen(aDetail);
if (len >= (int)sizeof(detail_str[dnext])) len = (sizeof(detail_str[dnext]) - 1);
memcpy(detail_str[dnext],aDetail,len);
detail_str[dnext][len] = 0;
detail_idx ^= 1;
}
/*--------------------------------------------------------------------------*/
int SessionObject::GetObjectSize(void)
{
int			mysize;

mysize = HashObject::GetObjectSize();
return(mysize);
}
/*--------------------------------------------------------------------------*/
char *SessionObject::GetObjectString(char *target,int maxlen)
{
const char		*local;

if (detail_str[detail_idx] == NULL) local = "";
else local = detail_str[detail_idx];

snprintf(target,maxlen,"%s [%d|%d|%s|%s|%s]",GetNetString(),state,confidence,application_str[application_idx],protochain_str[protochain_idx],local);

return(target);
}
/*--------------------------------------------------------------------------*/

