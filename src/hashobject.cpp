// HASHOBJECT.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2012 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
HashObject::HashObject(unsigned short aProto,const char *aHashname)
{
hashname = (char *)malloc(strlen(aHashname)+1);
strcpy(hashname,aHashname);
netproto = aProto;
next = NULL;

timeout = time(NULL);
if (netproto == IPPROTO_TCP) timeout+=cfg_tcp_timeout;
if (netproto == IPPROTO_UDP) timeout+=cfg_udp_timeout;
}
/*--------------------------------------------------------------------------*/
HashObject::~HashObject(void)
{
free(hashname);
}
/*--------------------------------------------------------------------------*/
int HashObject::GetObjectSize(void)
{
int			mysize;

mysize = sizeof(*this);
if (hashname != NULL) mysize+=(strlen(hashname) + 1);
return(mysize);
}
/*--------------------------------------------------------------------------*/
char *HashObject::GetObjectString(char *target,int maxlen)
{
snprintf(target,maxlen,"N:%s",hashname);
return(target);
}
/*--------------------------------------------------------------------------*/
void HashObject::ResetTimeout(void)
{
timeout = time(NULL);
if (netproto == IPPROTO_TCP) timeout+=cfg_tcp_timeout;
if (netproto == IPPROTO_UDP) timeout+=cfg_udp_timeout;
}
/*--------------------------------------------------------------------------*/
void HashObject::ScheduleExpiration(void)
{
timeout = (time(NULL) + cfg_purge_delay);
}
/*--------------------------------------------------------------------------*/

