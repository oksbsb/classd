// NETSERVER.CPP
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
NetworkServer::NetworkServer(void)
{
struct sockaddr_in	addr;
int					ret,val;

// initialize our member variables
ClientList = NULL;

// initialize the thread control semaphore so we start suspended
sem_init(&ThreadSignal,0,0);

// spin up a new thread
pthread_create(&ThreadHandle,NULL,ThreadMaster,this);

// allocate our main server socket
netsock = socket(AF_INET,SOCK_STREAM,0);

// set the reuse address option
val = 1;
ret = setsockopt(netsock,SOL_SOCKET,SO_REUSEADDR,(char *)&val,sizeof(val));
if (ret == -1) logmessage(LOG_ERR,"Error %d returned from network setsockopt(SO_REUSEADDR)",errno);

// set the socket to non blocking mode
ret = fcntl(netsock,F_SETFL,O_NONBLOCK);
if (ret == -1) logmessage(LOG_ERR,"Error %d returned from network fcntl(O_NONBLOCK)",errno);

// bind the socket to our server port
memset(&addr,0,sizeof(addr));
addr.sin_family = AF_INET;
addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
addr.sin_port = htons(cfg_share_port);
ret = bind(netsock,(struct sockaddr *)&addr,sizeof(addr));
if (ret == -1) logmessage(LOG_ERR,"Error %d returned from bind(netsock)",errno);

// listen for incomming connections
ret = listen(netsock,8);
if (ret == -1) logmessage(LOG_ERR,"Error %d returned from listen()",errno);
}
/*--------------------------------------------------------------------------*/
NetworkServer::~NetworkServer(void)
{
NetworkClient		*curr,*next;
int					ret;

// set the thread signal semaphore
sem_post(&ThreadSignal);

// interrupt the running thread
pthread_kill(ThreadHandle,SIGTERM);

// wait for the thread to terminate
pthread_join(ThreadHandle,NULL);

	// delete any active clients
	for(curr = ClientList;curr != NULL;)
	{
	next = curr->next;
	delete(curr);
	curr = next;
	}

	// clean up the server socket
	if (netsock > 0)
	{
	ret = shutdown(netsock,SHUT_RDWR);
	if (ret != 0) logmessage(LOG_ERR,"Error %d returned from shutdown()",errno);

	ret = close(netsock);
	if (ret != 0) logmessage(LOG_ERR,"Error %d returned from close()",errno);
	}
}
/*--------------------------------------------------------------------------*/
void* NetworkServer::ThreadMaster(void *argument)
{
NetworkServer		*mypointer = (NetworkServer *)argument;
void				*retval;

// set the itimer value of the main thread which is required
// for gprof to work properly with multithreaded applications
setitimer(ITIMER_PROF,&g_itimer,NULL);

// wait for the control semaphore so we don't start
// running before the constructor has finished
sem_wait(&mypointer->ThreadSignal);

// pass execution to our member worker function which
// will not return until our destructor is called
retval = mypointer->ThreadWorker();

// return to caller
return(retval);
}
/*--------------------------------------------------------------------------*/
void NetworkServer::BeginExecution(void)
{
// signal the thread
sem_post(&ThreadSignal);
}
/*--------------------------------------------------------------------------*/
void* NetworkServer::ThreadWorker(void)
{
NetworkClient		*local,*curr,*next;
struct timeval		tv;
fd_set				tester;
int					ret,val,max;

logmessage(LOG_INFO,"The netserver thread is starting\n");

	for(;;)
	{
	// watch the thread signal for termination
	val = 0;
	ret = sem_getvalue(&ThreadSignal,&val);
	if (ret != 0) break;
	if (val != 0) break;

	// clear our set and add the main server socket
	FD_ZERO(&tester);
	FD_SET(netsock,&tester);
	max = netsock;

		// add each network client to the set
		for(local = ClientList;local != NULL;local = local->next)
		{
		FD_SET(local->netsock,&tester);
		if (local->netsock > max) max = local->netsock;
		}

	// wait for something to happen
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret = select(max+1,&tester,NULL,NULL,&tv);
	if (ret < 1) continue;

		// handle new client connections
		if (FD_ISSET(netsock,&tester) != 0)
		{
			try
			{
			local = new NetworkClient(netsock);
			}

			catch(Problem *err)
			{
			logproblem(err);
			local = NULL;
			}

		if (local != NULL) InsertClient(local);
		}

		// check all the network clients for activity
		for(curr = ClientList;curr != NULL;)
		{
		next = curr->next;

			if (FD_ISSET(curr->netsock,&tester) != 0)
			{
			ret = curr->NetworkHandler();
			if (ret == 0) RemoveClient(curr);
			}

		curr = next;
		}
	}

logmessage(LOG_INFO,"The netserver thread has terminated\n");
return(NULL);
}
/*--------------------------------------------------------------------------*/
void NetworkServer::InsertClient(NetworkClient *aClient)
{
// insert the new client at the front of the linked list
aClient->next = ClientList;
ClientList = aClient;
}
/*--------------------------------------------------------------------------*/
void NetworkServer::RemoveClient(NetworkClient *aClient)
{
NetworkClient	*work,*prev;

// start with empty previous pointer
prev = NULL;

	// walk through the list and look for a match
	for(work = ClientList;work != NULL;work = work->next)
	{
		// if we find it pull it out of the chain and delete
		if (work == aClient)
		{
		// if item being deleted is first pull out front of list
		if (work == ClientList) ClientList = work->next;

		// otherwise pull out of the middle of the list
		else if (prev != NULL) prev->next = work->next;

		// delete the item we pulled out of the linked list
		delete(work);

		// break out of the loop
		break;
		}

	// save current pointer as previous
	prev = work;
	}
}
/*--------------------------------------------------------------------------*/

