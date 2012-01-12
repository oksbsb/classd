// MESSAGE.CPP
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
MessageQueue::MessageQueue(void)
{
// initialize our head and tail pointers
ListHead = ListTail = NULL;
memset(&MessageSignal,0,sizeof(MessageSignal));
memset(&ListLock,0,sizeof(ListLock));

// initialize our lock mutex
pthread_mutex_init(&ListLock,NULL);

// create our signal semaphore
sem_init(&MessageSignal,0,0);

counter = 0;
hicount = 0;
}
/*--------------------------------------------------------------------------*/
MessageQueue::~MessageQueue(void)
{
// clean up our signal semaphore
sem_destroy(&MessageSignal);

// clean up our lock mutex
pthread_mutex_destroy(&ListLock);

	// cleanup any messages left in the queue
	while (ListHead != NULL)
	{
	ListTail = ListHead->next;
	delete(ListHead);
	ListHead = ListTail;
	}
}
/*--------------------------------------------------------------------------*/
void MessageQueue::PushMessage(MessageWagon *argMessage)
{
// lock our mutex
pthread_mutex_lock(&ListLock);

	// if queue is empty assign message to tail pointer
	if (ListTail == NULL)
	{
	ListTail = argMessage;
	}

	// otherwise append to the current tail object
	else
	{
	ListTail->next = argMessage;
	ListTail = argMessage;
	}

// if head is null copy the tail
if (ListHead == NULL) ListHead = ListTail;

// increment the message signal semaphore
sem_post(&MessageSignal);

// increment our counter and track highest value
counter++;
if (counter > hicount) hicount = counter;

// unlock our mutex
pthread_mutex_unlock(&ListLock);
}
/*--------------------------------------------------------------------------*/
MessageWagon* MessageQueue::GrabMessage(void)
{
MessageWagon		*local;

// wait for a message
sem_wait(&MessageSignal);

// lock our mutex
pthread_mutex_lock(&ListLock);

	// list is empty
	if (ListHead == NULL)
	{
	local = NULL;
	}

	// list has single item
	else if (ListHead == ListTail)
	{
	local = ListHead;
	ListHead = ListTail = NULL;
	}

	// grab the first item in the list
	else
	{
	local = ListHead;
	ListHead = local->next;
	}

// decrement our counter
counter--;

// unlock our mutex
pthread_mutex_unlock(&ListLock);

// return the message
return(local);
}
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
MessageWagon::MessageWagon(int argCommand,const unsigned char *argBuffer,int argLength)
{
next = NULL;
command = argCommand;
length = argLength;
buffer = (unsigned char *)malloc(argLength);
memcpy(buffer,argBuffer,argLength);
}
/*--------------------------------------------------------------------------*/
MessageWagon::MessageWagon(int argCommand)
{
next = NULL;
command = argCommand;
length = 0;
buffer = NULL;
}
/*--------------------------------------------------------------------------*/
MessageWagon::~MessageWagon(void)
{
if (buffer != NULL) free(buffer);
}
/*--------------------------------------------------------------------------*/

