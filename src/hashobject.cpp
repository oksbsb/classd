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
	const char *aProtocol,
	const char *aDetail,
	short aConfidence,
	short aState)
{
network = aNetwork;

hashname = (char *)malloc(strlen(aHashname)+1);
strcpy(hashname,aHashname);

application = (char *)malloc(strlen(aApplication)+1);
strcpy(application,aApplication);

protocol = (char *)malloc(strlen(aProtocol)+1);
strcpy(protocol,aProtocol);

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
free(protocol);
free(detail);
}
/*--------------------------------------------------------------------------*/
void HashObject::UpdateObject(const char *aApplication,
	const char *aProtocol,
	const char *aDetail,
	short aConfidence,
	short aState)
{
application = (char *)realloc(application,strlen(aApplication)+1);
strcpy(application,aApplication);

protocol = (char *)realloc(protocol,strlen(aProtocol)+1);
strcpy(protocol,aProtocol);

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
if (protocol != NULL) mysize+=(strlen(protocol) + 1);
if (detail != NULL) mysize+=(strlen(detail) + 1);
return(mysize);
}
/*--------------------------------------------------------------------------*/

