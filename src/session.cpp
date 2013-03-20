// SESSION.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2013 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
SessionObject::SessionObject(const char *aHashname,
	u_int8_t aNetProto,
	u_int32_t aClientAddr,
	u_int16_t aClientPort,
	u_int32_t aServerAddr,
	u_int16_t aServerPort) : HashObject(aNetProto,aHashname)
{
application = NULL;
protochain = NULL;
detail = NULL;

confidence = 0;
state = 0;

upcount = 0;

clientaddr = aClientAddr;
clientport = aClientPort;
serveraddr = aServerAddr;
serverport = aServerPort;
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

upcount++;
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
snprintf(target,maxlen,"%s [%d|%d|%s|%s|%s]",GetHashname(),confidence,state,application,protochain,local);
return(target);
}
/*--------------------------------------------------------------------------*/

