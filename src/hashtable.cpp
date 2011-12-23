// HASHTABLE.CPP
// Traffic Classification Engine
// Copyright (c) 2011 Untangle, Inc.
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
control = (sem_t *)calloc(buckets,sizeof(sem_t));
for(x = 0;x < buckets;x++) sem_init(&control[x],0,1);
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
for(x = 0;x < buckets;x++) sem_destroy(&control[x]);
free(control);
}
/*--------------------------------------------------------------------------*/
int HashTable::InsertObject(HashObject *aObject)
{
unsigned			key;

// calculate bucket using the hash function
key = GetHashValue(aObject->hashname);

// lock the bucket
sem_wait(&control[key]);

// save existing item in new item next pointer
aObject->next = table[key];

// put new item at front of list
table[key] = aObject;

// unlock the bucket
sem_post(&control[key]);

return(key);
}
/*--------------------------------------------------------------------------*/
int HashTable::DeleteObject(HashObject *aObject)
{
HashObject	*work,*prev;
unsigned	key;

// calculate bucket using the hash function
key = GetHashValue(aObject->hashname);

// lock the bucket
sem_wait(&control[key]);

	// if bucket is empty just unlock and return
	if (table[key] == NULL)
	{
	sem_post(&control[key]);
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
		sem_post(&control[key]);

		// return one item deleted
		return(1);
		}

	// save current pointer as previous
	prev = work;
	}

// unlock the bucket
sem_post(&control[key]);

return(0);
}
/*--------------------------------------------------------------------------*/
void HashTable::ExpireObject(HashObject *aObject)
{
aObject->timeout = (time(NULL) + cfg_purge_delay);
}
/*--------------------------------------------------------------------------*/
HashObject* HashTable::SearchObject(const char *aHashname)
{
HashObject	*find;
unsigned	key;

// calculate bucket using the hash function
key = GetHashValue(aHashname);

// lock the bucket
sem_wait(&control[key]);

	// if the bucket is empty unlock and return nothing
	if (table[key] == NULL)
	{
	sem_post(&control[key]);
	return(NULL);
	}

	// search for exact match or default
	for(find = table[key];find != NULL;find = find->next)
	{
	if (find->next == find) break;
	if (strcmp(aHashname,find->hashname) != 0) continue;

	// unlock the bucket
	sem_post(&control[key]);

	// return object found
	return(find);
	}

// unlocko and return NULL if nothing found
sem_post(&control[key]);
return(NULL);
}
/*--------------------------------------------------------------------------*/
int HashTable::PurgeStaleObjects(time_t aStamp)
{
HashObject	*prev,*curr,*next;
int			removed;
int			kill;
int			x;

removed = 0;

	for(x = 0;x < buckets;x++)
	{
	// lock the bucket
	sem_wait(&control[x]);

		// if bucket is empty just unlock and continue
		if (table[x] == NULL)
		{
		sem_post(&control[x]);
		continue;
		}

	// start with first item and a clear prev pointer
	curr = table[x];
	prev = NULL;

		while (curr != NULL)
		{
		kill = 0;

			// look for stale TCP objects
			if ((curr->netproto == IPPROTO_TCP) && (aStamp > curr->timeout))
			{
			g_tcp_cleanup++;
			kill++;
			}

			// look for stale UDP objects
			if ((curr->netproto == IPPROTO_UDP) && (aStamp > curr->timeout))
			{
			g_udp_cleanup++;
			kill++;
			}

			// if not stale adjust working pointers and continue
			if (kill == 0)
			{
			prev = curr;
			curr = curr->next;
			continue;
			}

		// if item being deleted is first remove from beginning of list
		if (curr == table[x]) table[x] = curr->next;

		// otherwise pull out of the middle of the list
		else if (prev != NULL) prev->next = curr->next;

		// save pointer to next and delete
		next = curr->next;
		delete(curr);
		removed++;

		// adjust current to next in bucket
		curr = next;
		}

	// unlock the bucket
	sem_post(&control[x]);
	}

return(removed);
}
/*--------------------------------------------------------------------------*/
unsigned int HashTable::GetHashValue(const void *aString)
{
const unsigned char	*s = (unsigned char *)aString;
unsigned int			total;

for(total = 0;*s;s++) total = (613 * total + s[0]);
return(total % buckets);
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
aBytes+=(buckets * sizeof(sem_t));

	// walk through all of the table entries
	for(x = 0;x < buckets;x++)
	{
	// lock the bucket
	sem_wait(&control[x]);

		// count an add the size of every object
		if (table[x] != NULL)
		{
			for(work = table[x];work != NULL;work = work->next)
			{
			aBytes+=work->GetObjectSize();
			aCount++;
			}
		}

	// unlock the bucket
	sem_post(&control[x]);
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
bytes+=(buckets * sizeof(sem_t));

	// walk through all of the table entries
	for(x = 0;x < buckets;x++)
	{
	// lock the bucket
	sem_wait(&control[x]);

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
	sem_post(&control[x]);
	}

fprintf(aFile,"  TOTAL ITEMS = %d\n",count);
fprintf(aFile,"  TOTAL BYTES = %d\n",bytes);
}
/*--------------------------------------------------------------------------*/

