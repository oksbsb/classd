// STATOBJECT.CPP
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
StatusObject::StatusObject(unsigned short aNetwork,const char *aHashname,void *aTracker) : HashObject(aNetwork,aHashname)
{
tracker = aTracker;

application = NULL;
protochain = NULL;
detail = NULL;

confidence = 0;
state = 0;
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
void StatusObject::GetObjectString(char *target,int maxlen)
{
snprintf(target,maxlen,"%s [%s|%s|%s|%d|%d]",GetHashname(),application,protochain,detail,confidence,state);
}
/*--------------------------------------------------------------------------*/

