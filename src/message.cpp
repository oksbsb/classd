// MESSAGE.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2018 Untangle, Inc.
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
memset(&ListLock,0,sizeof(ListLock));
pthread_mutex_init(&ListLock,NULL);

// create our signal semaphore
sem_init(&MessageSignal,0,0);

curr_count = 0;
curr_bytes = 0;
high_count = 0;
high_bytes = 0;
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

	// if we have reached the configured limit just throw it away
	if (curr_count >= cfg_packet_maximum)
	{
	// delete the message and increment the counter
	delete(argMessage);
	msg_sizedrop++;

	// unlock our mutex
	pthread_mutex_unlock(&ListLock);
	return;
	}

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

// increment our count and memory trackers
curr_count++;
if (curr_count > high_count) high_count = curr_count;
curr_bytes+=argMessage->length;
if (curr_bytes > high_bytes) high_bytes = curr_bytes;

// increment the packet counter
msg_totalcount++;

// unlock our mutex
pthread_mutex_unlock(&ListLock);

// increment the message signal semaphore
sem_post(&MessageSignal);
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
curr_count--;
if (local != NULL) curr_bytes-=local->length;

// unlock our mutex
pthread_mutex_unlock(&ListLock);

// return the message
return(local);
}
/*--------------------------------------------------------------------------*/
void MessageQueue::GetQueueSize(int &aCurr_count,int &aCurr_bytes,int &aHigh_count,int &aHigh_bytes)
{
aCurr_count = curr_count;
aCurr_bytes = curr_bytes;
aHigh_count = high_count;
aHigh_bytes = high_bytes;
}
/*--------------------------------------------------------------------------*/
/*--------------------------------------------------------------------------*/
MessageWagon::MessageWagon(u_int8_t argCommand,u_int64_t argIndex,const void *argBuffer,int argLength)
{
next = NULL;
command = argCommand;
index = argIndex;
length = argLength;
buffer = (unsigned char *)malloc(argLength);
memcpy(buffer,argBuffer,argLength);
timestamp = time(NULL);
}
/*--------------------------------------------------------------------------*/
MessageWagon::MessageWagon(u_int8_t argCommand,const char *argString)
{
next = NULL;
command = argCommand;
index = 0;
length = (strlen(argString) + 1);
buffer = (unsigned char *)malloc(length);
strcpy((char *)buffer,argString);
timestamp = time(NULL);
}
/*--------------------------------------------------------------------------*/
MessageWagon::MessageWagon(u_int8_t argCommand,u_int64_t argIndex)
{
next = NULL;
command = argCommand;
index = argIndex;
length = 0;
buffer = NULL;
}
/*--------------------------------------------------------------------------*/
MessageWagon::MessageWagon(u_int8_t argCommand)
{
next = NULL;
command = argCommand;
index = 0;
length = 0;
buffer = NULL;
}
/*--------------------------------------------------------------------------*/
MessageWagon::~MessageWagon(void)
{
if (buffer != NULL) free(buffer);
}
/*--------------------------------------------------------------------------*/

