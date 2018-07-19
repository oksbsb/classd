// EXTERNALS.CPP
// Traffic Classification Engine
// Copyright (c) 2011-2018 Untangle, Inc.
// All Rights Reserved
// Written by Michael A. Hotz

#include "common.h"
#include "classd.h"
/*--------------------------------------------------------------------------*/
void navl_bind_externals(void)
{
/* memory allocation */
navl_malloc_local = malloc;
navl_free_local = free;
navl_malloc_shared = malloc;
navl_free_shared = free;

/* ctype */
navl_islower = islower;
navl_isupper = isupper;
navl_tolower = tolower;
navl_toupper = toupper;
navl_isalnum = isalnum;
navl_isspace = isspace;
navl_isdigit = isdigit;

/* string functions */
navl_atoi = atoi;
navl_memcpy = memcpy;
navl_memcmp = memcmp;
navl_memset = memset;
navl_strcasecmp = strcasecmp;
navl_strchr = (const char* (*)(const char*, int))strchr;
navl_strrchr = (const char* (*)(const char*, int))strrchr;
navl_strcmp = strcmp;
navl_strncmp = strncmp;
navl_strcpy = strcpy;
navl_strncpy = strncpy;
navl_strerror = strerror;
navl_strftime = (size_t (*)(char*, size_t, const char*, const struct navl_tm*))strftime;
navl_strlen = strlen;
navl_strpbrk = (const char* (*)(const char*, const char*))strpbrk;
navl_strstr = (const char* (*)(const char*, const char*))strstr;
navl_strtol = strtol;

/* input/output */
navl_printf = printf;
navl_sprintf = sprintf;
navl_snprintf = snprintf;
navl_sscanf = sscanf;
navl_putchar = putchar;
navl_puts = puts;
navl_diag_printf = vineyard_printf;

/* time */
navl_gettimeofday = (int (*)(struct navl_timeval*, void*))gettimeofday;
navl_mktime = (navl_time_t (*)(struct navl_tm*))mktime;

/* math */
navl_log = log;
navl_fabs = fabs;

/* system */
navl_abort = abort;
navl_get_thread_id = (unsigned long (*)(void))pthread_self;
navl_log_message = vineyard_logger;
}
/*--------------------------------------------------------------------------*/

