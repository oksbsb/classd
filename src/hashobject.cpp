// HASHOBJECT.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2018 Untangle, Inc.
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

ResetTimeout();

snprintf(netstring,sizeof(netstring),"%" PRIu64,netsession);
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

	switch(netprotocol)
	{
	case IPPROTO_TCP:
		timeout+=cfg_tcp_timeout;
		break;
	case IPPROTO_UDP:
		timeout+=cfg_udp_timeout;
		break;
	case IPPROTO_IP:
	case IPPROTO_IPV6:
		timeout+=cfg_ip_timeout;
		break;
	default:
		timeout+=3600;
	}
}
/*--------------------------------------------------------------------------*/

