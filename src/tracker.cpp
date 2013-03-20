// TRACKER.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2013 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
TrackerObject::TrackerObject(unsigned short aNetwork,const char *aHashname) : HashObject(aNetwork,aHashname)
{
orig_saddr = 0;
orig_sport = 0;
orig_daddr = 0;
orig_dport = 0;
}
/*--------------------------------------------------------------------------*/
TrackerObject::~TrackerObject(void)
{
}
/*--------------------------------------------------------------------------*/
void TrackerObject::UpdateObject(u_int32_t aSaddr,u_int16_t aSport,u_int32_t aDaddr,u_int16_t aDport)
{
ResetTimeout();
orig_saddr = aSaddr;
orig_sport = aSport;
orig_daddr = aDaddr;
orig_dport = aDport;
}
/*--------------------------------------------------------------------------*/
int TrackerObject::GetObjectSize(void)
{
int			mysize;

mysize = HashObject::GetObjectSize();
return(mysize);
}
/*--------------------------------------------------------------------------*/
char *TrackerObject::GetObjectString(char *target,int maxlen)
{
struct in_addr	saddr,daddr;
char			srcname[32];
char			dstname[32];

saddr.s_addr = orig_saddr;
daddr.s_addr = orig_daddr;
strcpy(srcname,inet_ntoa(saddr));
strcpy(dstname,inet_ntoa(daddr));

snprintf(target,maxlen,"%s [%s:%u-%s:%u]",GetHashname(),dstname,ntohs(orig_dport),srcname,ntohs(orig_sport));
return(target);
}
/*--------------------------------------------------------------------------*/

