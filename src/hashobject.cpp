// HASHOBJECT.C
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
HashObject::HashObject(unsigned short aNetwork,
	const char *aHashname,
	const char *aApplication,
	const char *aProtochain,
	const char *aDetail,
	short aConfidence,
	short aState)
{
network = aNetwork;

hashname = (char *)malloc(strlen(aHashname)+1);
strcpy(hashname,aHashname);

application = (char *)malloc(strlen(aApplication)+1);
strcpy(application,aApplication);

protochain = (char *)malloc(strlen(aProtochain)+1);
strcpy(protochain,aProtochain);

detail = (char *)malloc(strlen(aDetail)+1);
strcpy(detail,aDetail);

confidence = aConfidence;
state = aState;

timestamp = time(NULL);
next = NULL;
}
/*--------------------------------------------------------------------------*/
HashObject::~HashObject(void)
{
free(hashname);
free(application);
free(protochain);
free(detail);
}
/*--------------------------------------------------------------------------*/
void HashObject::UpdateObject(const char *aApplication,
	const char *aProtochain,
	const char *aDetail,
	short aConfidence,
	short aState)
{
application = (char *)realloc(application,strlen(aApplication)+1);
strcpy(application,aApplication);

protochain = (char *)realloc(protochain,strlen(aProtochain)+1);
strcpy(protochain,aProtochain);

detail = (char *)realloc(detail,strlen(aDetail)+1);
strcpy(detail,aDetail);

confidence = aConfidence;
state = aState;

timestamp = time(NULL);
}
/*--------------------------------------------------------------------------*/
int HashObject::GetObjectSize(void)
{
int			mysize;

mysize = sizeof(*this);
if (hashname != NULL) mysize+=(strlen(hashname) + 1);
if (application != NULL) mysize+=(strlen(application) + 1);
if (protochain != NULL) mysize+=(strlen(protochain) + 1);
if (detail != NULL) mysize+=(strlen(detail) + 1);
return(mysize);
}
/*--------------------------------------------------------------------------*/
void HashObject::GetObjectString(char *target,int maxlen)
{
snprintf(target,maxlen,"N:%s A:%s P:%s D:%s C:%d S:%d",hashname,application,protochain,detail,confidence,state);
}
/*--------------------------------------------------------------------------*/

