// HASHTABLE.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2018 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
HashTable::HashTable(int aBuckets)
{
int		x;

// save the number of buckets
buckets = aBuckets;

// allocate the bucket array
table = (HashObject **)calloc(buckets,sizeof(HashObject *));

// allocate and initialize the bucket locks
control = (pthread_mutex_t *)calloc(buckets,sizeof(pthread_mutex_t));

	for(x = 0;x < buckets;x++)
	{
	memset(&control[0],0,sizeof(pthread_mutex_t));
	pthread_mutex_init(&control[x],NULL);
	}
}
/*--------------------------------------------------------------------------*/
HashTable::~HashTable(void)
{
HashObject	*work,*hold;
int			x;

	// walk through all the buckets and delete everything
	for(x = 0;x < buckets;x++)
	{
	if (table[x] == NULL) continue;
	work = table[x];

		while (work != NULL)
		{
		hold = work->next;
		delete(work);
		work = hold;
		}
	}

// free the bucket array
free(table);

// free the bucket locks
for(x = 0;x < buckets;x++) pthread_mutex_destroy(&control[x]);
free(control);
}
/*--------------------------------------------------------------------------*/
int HashTable::InsertObject(HashObject *aObject)
{
unsigned			key;

// calculate bucket using the hash function
key = GetHashValue(aObject->netsession);

// lock the bucket
pthread_mutex_lock(&control[key]);

// save existing item in new item next pointer
aObject->next = table[key];

// put new item at front of list
table[key] = aObject;

// unlock the bucket
pthread_mutex_unlock(&control[key]);

return(key);
}
/*--------------------------------------------------------------------------*/
int HashTable::DeleteObject(HashObject *aObject)
{
HashObject	*work,*prev;
unsigned	key;

// calculate bucket using the hash function
key = GetHashValue(aObject->netsession);

// lock the bucket
pthread_mutex_lock(&control[key]);

	// if bucket is empty just unlock and return
	if (table[key] == NULL)
	{
	pthread_mutex_unlock(&control[key]);
	return(0);
	}

// start with empty previous pointer
prev = NULL;

	// walk through the bucket and look for a match
	for(work = table[key];work != NULL;work = work->next)
	{
		// if we find it pull it out of the chain and delete
		if (work == aObject)
		{
		// if item being deleted is first pull out front of list
		if (work == table[key]) table[key] = work->next;

		// otherwise pull out of the middle of the list
		else if (prev != NULL) prev->next = work->next;

		// delete the item we pulled out of the linked list
		delete(work);

		// unlock the bucket
		pthread_mutex_unlock(&control[key]);

		// return one item deleted
		return(1);
		}

	// save current pointer as previous
	prev = work;
	}

// unlock the bucket
pthread_mutex_unlock(&control[key]);

return(0);
}
/*--------------------------------------------------------------------------*/
HashObject* HashTable::SearchObject(u_int64_t aValue)
{
HashObject	*find;
unsigned	key;

// calculate bucket using the hash function
key = GetHashValue(aValue);

// lock the bucket
pthread_mutex_lock(&control[key]);

	// if the bucket is empty unlock and return nothing
	if (table[key] == NULL)
	{
	pthread_mutex_unlock(&control[key]);
	return(NULL);
	}

	// search for exact match or default
	for(find = table[key];find != NULL;find = find->next)
	{
	if (find->next == find) break;
	if (aValue != find->netsession) continue;

	// unlock the bucket
	pthread_mutex_unlock(&control[key]);

	// return object found
	return(find);
	}

// unlocko and return NULL if nothing found
pthread_mutex_unlock(&control[key]);
return(NULL);
}
/*--------------------------------------------------------------------------*/
int HashTable::PurgeStaleObjects(time_t aStamp)
{
HashObject	*work;
int			removed;
int			kill;
int			x;

removed = 0;

	for(x = 0;x < buckets;x++)
	{
	// lock the bucket
	pthread_mutex_lock(&control[x]);

		// check every object in each active table
		if (table[x] != NULL)
		{
			for(work = table[x];work != NULL;work = work->next)
			{
			kill = 0;

			// look for stale TCP objects
			if ((work->netprotocol == IPPROTO_TCP) && (aStamp > work->timeout)) kill++;

			// look for stale UDP objects
			if ((work->netprotocol == IPPROTO_UDP) && (aStamp > work->timeout)) kill++;

			if (kill == 0) continue;

			// if stale post a remove message to the classify thread
			g_messagequeue->PushMessage(new MessageWagon(MSG_REMOVE,work->netsession));
			removed++;
			}
		}

	// unlock the bucket
	pthread_mutex_unlock(&control[x]);
	}

return(removed);
}
/*--------------------------------------------------------------------------*/
u_int64_t HashTable::GetHashValue(u_int64_t aValue)
{
return((u_int64_t)aValue % (u_int64_t)buckets);
}
/*--------------------------------------------------------------------------*/
void HashTable::GetTableSize(int &aCount,int &aBytes)
{
HashObject	*work;
int			x;

aCount = 0;
aBytes = 0;

// start with our size
aBytes = sizeof(*this);
aBytes+=(buckets * sizeof(HashObject *));
aBytes+=(buckets * sizeof(pthread_mutex_t));

	// walk through all of the table entries
	for(x = 0;x < buckets;x++)
	{
	// lock the bucket
	pthread_mutex_lock(&control[x]);

		// count and add the size of every object in active tables
		if (table[x] != NULL)
		{
			for(work = table[x];work != NULL;work = work->next)
			{
			aBytes+=work->GetObjectSize();
			aCount++;
			}
		}

	// unlock the bucket
	pthread_mutex_unlock(&control[x]);
	}
}
/*--------------------------------------------------------------------------*/
void HashTable::DumpDetail(FILE *aFile)
{
HashObject	*work;
char		buffer[256];
int			count,bytes;
int			x;

count = 0;
bytes = 0;

// start with our size
bytes = sizeof(*this);
bytes+=(buckets * sizeof(HashObject *));
bytes+=(buckets * sizeof(pthread_mutex_t));

	// walk through all of the table entries
	for(x = 0;x < buckets;x++)
	{
	// lock the bucket
	pthread_mutex_lock(&control[x]);

		// count an add the size of every object
		if (table[x] != NULL)
		{
			for(work = table[x];work != NULL;work = work->next)
			{
			work->GetObjectString(buffer,sizeof(buffer));
			fprintf(aFile,"  %d = %s\n",x,buffer);
			bytes+=work->GetObjectSize();
			count++;
			}
		}

	// unlock the bucket
	pthread_mutex_unlock(&control[x]);
	}

fprintf(aFile,"  TOTAL ITEMS = %d\n",count);
fprintf(aFile,"  TOTAL BYTES = %d\n",bytes);
}
/*--------------------------------------------------------------------------*/

