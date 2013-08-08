// HASHOBJECT.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2013 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
HashObject::HashObject(u_int64_t aSession,u_int16_t aProtocol)
{
netprotocol = aProtocol;
netsession = aSession;
timeout = time(NULL);
next = NULL;

if (netprotocol == IPPROTO_TCP) timeout+=cfg_tcp_timeout;
if (netprotocol == IPPROTO_UDP) timeout+=cfg_udp_timeout;

snprintf(netstring,sizeof(netstring),"%"PRI64u,netsession);
}
/*--------------------------------------------------------------------------*/
HashObject::~HashObject(void)
{
}
/*--------------------------------------------------------------------------*/
int HashObject::GetObjectSize(void)
{
int			mysize;

mysize = sizeof(*this);
return(mysize);
}
/*--------------------------------------------------------------------------*/
void HashObject::ResetTimeout(void)
{
timeout = time(NULL);
if (netprotocol == IPPROTO_TCP) timeout+=cfg_tcp_timeout;
if (netprotocol == IPPROTO_UDP) timeout+=cfg_udp_timeout;
}
/*--------------------------------------------------------------------------*/

