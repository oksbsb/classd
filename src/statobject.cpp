// STATOBJECT.CPP
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
StatusObject::StatusObject(const char *aHashname,
	uint8_t aNetProto,
	uint32_t aClientAddr,
	uint16_t aClientPort,
	uint32_t aServerAddr,
	uint16_t aServerPort) : HashObject(aNetProto,aHashname)
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

clientfin = serverfin = 0;
}
/*--------------------------------------------------------------------------*/
StatusObject::~StatusObject(void)
{
if (application != NULL) free(application);
if (protochain != NULL) free(protochain);
if (detail != NULL) free(detail);
}
/*--------------------------------------------------------------------------*/
void StatusObject::UpdateObject(const char *aApplication,
	const char *aProtochain,
	const char *aDetail,
	short aConfidence,
	short aState)
{
HashObject::UpdateObject();

application = (char *)realloc(application,strlen(aApplication)+1);
strcpy(application,aApplication);

protochain = (char *)realloc(protochain,strlen(aProtochain)+1);
strcpy(protochain,aProtochain);

detail = (char *)realloc(detail,strlen(aDetail)+1);
strcpy(detail,aDetail);

confidence = aConfidence;
state = aState;

upcount++;
}
/*--------------------------------------------------------------------------*/
int StatusObject::GetObjectSize(void)
{
int			mysize;

mysize = HashObject::GetObjectSize();
if (application != NULL) mysize+=(strlen(application) + 1);
if (protochain != NULL) mysize+=(strlen(protochain) + 1);
if (detail != NULL) mysize+=(strlen(detail) + 1);
return(mysize);
}
/*--------------------------------------------------------------------------*/
char *StatusObject::GetObjectString(char *target,int maxlen)
{
snprintf(target,maxlen,"%s [%d|%d|%s|%s|%s]",GetHashname(),confidence,state,application,protochain,detail);
return(target);
}
/*--------------------------------------------------------------------------*/

