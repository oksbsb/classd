#ifndef NAVL_H
#define NAVL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/*******************************************************************************
* Types and constants
*******************************************************************************/

typedef enum {
	NAVL_STATE_TERMINATED = 0,	/* Indicates the connection has been terminated */
	NAVL_STATE_INSPECTING = 1,	/* Indicates the connection is under inspection */
	NAVL_STATE_MONITORING = 2,	/* Indicates the connection is under inspection */
	NAVL_STATE_CLASSIFIED = 3	/* Indicates the connection is fully classified */
} navl_state_t;

typedef enum {
	NAVL_ENCAP_NONE = 0,
	NAVL_ENCAP_ETH  = 1,
	NAVL_ENCAP_IP   = 2,
	NAVL_ENCAP_IP6  = 3
} navl_encap_t;

#define NAVL_AF_UNSPEC  0
#define NAVL_AF_INET    1
#define NAVL_AF_INET6   2

typedef struct navl_host {
	unsigned char  family;
	unsigned char  padding;
	unsigned short port;
	union {
		unsigned int  in4_addr;
		unsigned char in6_addr[16];
	};
} navl_host_t;

enum {
	NAVL_ATTR_F_FRAGMENT = (1 << 0)
};

enum {
	NAVL_CONN_F_CLASSIFICATION = (1 << 0),
	NAVL_CONN_F_CHAMELEON = (1 << 1),
	NAVL_CONN_F_FUTUREFLOWS = (1 << 2),
	NAVL_CONN_F_ATTRIBUTES = (1 << 3),
	NAVL_CONN_F_TUNNELS = (1 << 4)
};

typedef void *navl_iterator_t;
typedef void *navl_result_t;
typedef int navl_handle_t;
typedef void *navl_conn_t;
typedef uint64_t navl_conn_id_t;
typedef uint32_t navl_conn_flags_t;


/*******************************************************************************
* Library instance/thread initialization
*******************************************************************************/

/* Opens a new navl instance and registers the available classification plugins.
 * On success, a handle for the instance is returned. On error, -1 is returned.
 */
navl_handle_t navl_open(const char *plugins);

/* Initializes a thread for the handle.
 * On success, 0 is returned. On error, -1 is returned.
 */
int navl_init(navl_handle_t handle);

/* Finalize a thread for the handle.
 * On success, 0 is returned. On error, -1 is returned.
 */
int navl_fini(navl_handle_t handle);

/* Closes the navl instance referenced by @handle.
 * On success, 0 is returned. On error, -1 is returned. 
 */
int navl_close(navl_handle_t handle);


/*******************************************************************************
* Main classification APIs 
*******************************************************************************/

/* Callback signature for navl_classify */
typedef int (*navl_classify_callback_t)(navl_handle_t handle, navl_result_t result, navl_state_t state
	, navl_conn_id_t conn, void *arg, int error);

/* Simple classification API. */
int navl_classify_simple(navl_handle_t handle, const void *data, unsigned short len, int *index);

/* Normal classification API */
int navl_classify(navl_handle_t handle, navl_encap_t encap, const void *data, unsigned short len
	, navl_conn_t conn, int direction, navl_classify_callback_t, void *arg);


/*******************************************************************************
* Classification result processing
*******************************************************************************/

/* Fills in the endpoint information associated with the connection id */
int navl_endpoint_get(navl_handle_t handle, navl_conn_id_t id, navl_host_t *src, navl_host_t *dst);

/* Returns the application protocol index for the result */
int navl_app_get(navl_handle_t handle, navl_result_t result, int *confidence);

/* Returns the first iterator in the result */
navl_iterator_t navl_proto_first(navl_handle_t handle, navl_result_t result);

/* Returns 1 if the iterator is valid */
int navl_proto_valid(navl_handle_t handle, navl_iterator_t it);

/* Returns the next iterator */
navl_iterator_t navl_proto_next(navl_handle_t handle, navl_iterator_t it);

/* Returns the prev iterator */
navl_iterator_t navl_proto_prev(navl_handle_t handle, navl_iterator_t it);

/* Returns an iterator pointing to the top most protocol */
navl_iterator_t navl_proto_top(navl_handle_t handle, navl_result_t result);

/* Returns an iterator pointing to the protocol @index */
navl_iterator_t navl_proto_find(navl_handle_t handle, navl_result_t result, int index);

/* Extracts the protocol from the iterator */
int navl_proto_get_index(navl_handle_t handle, navl_iterator_t it);

/* Extracts the protocol from the short name */
int navl_proto_find_index(navl_handle_t handle, const char *name);

/* Returns a pointer to the proto name */
const char *navl_proto_get_name(navl_handle_t handle, int index, char *buf, unsigned int size);


/*******************************************************************************
* Connection information
*******************************************************************************/

/* Returns the status flags assigned to this connection */
int navl_conn_status_flags_get(navl_handle_t handle, navl_conn_id_t conn, navl_conn_flags_t *flags);

/* Disables the policies in @flags for this connection */
int navl_conn_policy_flags_disable(navl_handle_t handle, navl_conn_id_t conn, navl_conn_flags_t flags);


/*******************************************************************************
* Connection management (IPv4 and IPv6)
*******************************************************************************/

/* Allocate connection state by 5-tuple */
int navl_conn_create(navl_handle_t handle, navl_host_t *shost, navl_host_t *dhost, unsigned char proto, navl_conn_t *conn);

/* Release previously allocated connection state */
int navl_conn_destroy(navl_handle_t handle, navl_conn_t conn);

/*******************************************************************************
* Protocol/index management
*******************************************************************************/

/* Returns the max protocol index */
int navl_proto_max_index(navl_handle_t handle);

/* Set the GUID protocol string @name to the value @index. Returns 0 on success, -1 on error. */
int navl_proto_set_index(navl_handle_t handle, const char *name, int index);


/*******************************************************************************
* AttributeMgr management
*******************************************************************************/

/* Callback signature for navl attributes */ 
typedef void (*navl_attr_callback_t)(navl_handle_t, navl_conn_id_t conn, int attr_type, int attr_length, const void *attr_value
	, int attr_flag, void *);

/*  Returns 0 on success or -1 if the attribute was not found. */
int navl_attr_callback_set(navl_handle_t handle, const char *attr, navl_attr_callback_t callback);

/* Returns the attribute key on success or -1 on if the attribute was not found. */
int navl_attr_key_get(navl_handle_t handle, const char *attr);


/*******************************************************************************
* Configuration
*******************************************************************************/

/* Directly set a configuration variable - use with caution! Returns 0 for success. */
int navl_config_set(navl_handle_t handle, const char *key, const char *val);

/* Get a configuration variable. Returns 0 for success */
int navl_config_get(navl_handle_t handle, const char *key, char *val, int size);

/* Dumps the entire configuration via navl_diag_printf. Note in order to use this 
 * you must bind navl_diag_printf to a valid callback function.
 */
int navl_config_dump(navl_handle_t handle);


/*******************************************************************************
* NAVL internal clock manipulation
*******************************************************************************/

/* set and unset the clock mode - 0=auto, 1=manual */
void navl_clock_set_mode(navl_handle_t handle, int value);

/* manually set the wallclock time */
void navl_clock_set(navl_handle_t handle, int64_t msecs);


/*******************************************************************************
* Custom protocols and rules
*******************************************************************************/

/* Create and register a custom protocol with the given string name @protoname 
 * and a requested protocol @index (or zero for auto-assign). 
 * Returns protocol index if successful or -1 if error occurred including if the 
 * requested @index is already in use.
 */
int navl_proto_add(navl_handle_t handle, const char *protoname, int index);

/* Remove a custom protocol with the given string name.
 * Returns 0 for success, or -1 if an error occurred 
 */
int navl_proto_remove(navl_handle_t handle, const char *protoname);

/* Bind a protocol to a rule - either ip info or module/key/value or both may be specified.
 * Returns 0 for success, or -1 if an error occurred.
 */
int navl_rule_add(navl_handle_t handle, int index, const char *module, const char *rule);

/* Unbind a protocol from a rule.
 * Returns 0 for success, or -1 if error occurred.
 */
int navl_rule_remove(navl_handle_t handle, int index, const char *module, const char *rule);


/*******************************************************************************
* runtime utility functions
*******************************************************************************/

/* Returns the current value of the thread/instance-specific error */
int navl_error_get(navl_handle_t handle);

/* Perform necessary maintenance on idle thread - should be called at */
/* least once per second if thread is not calling navl classification api */
void navl_idle(navl_handle_t handle);

/* returns the navl instance handle active on the current thread */
/* may be used inside external functions to determine the active instance */
/* returns 0 on a thread on which navl_init has not been called */
navl_handle_t navl_handle_get(void);

/* Write diagnostic information for a module via navl_diag_printf */
int navl_diag(navl_handle_t handle, const char *module, const char *args);

/* Returns the current memory tags associated with this thread. The lower 16
 * bits contains a context (ctx) index/tag and the upper 16 bit contain an
 * object (obj) index/tag. */
int navl_memory_tag_get(navl_handle_t);

/* Returns the number of memory context identifiers */
int navl_memory_ctx_num(navl_handle_t);

/* Converts a context index retrived by navl_memory_tag_get() into a readable string */
int navl_memory_ctx_name(navl_handle_t, int, char *, int);

/* Returns the number of memory object identifiers */
int navl_memory_obj_num(navl_handle_t);

/* Converts an object index retrived by navl_memory_tag_get() into a readable string */
int navl_memory_obj_name(navl_handle_t, int, char *, int);


/*******************************************************************************
*** End of API declarations
*******************************************************************************/


/* The following section contains declarations of NAVL external functions.
   These functions are required by NAVL but are not bound initially. You
   must bind these function pointers to real functions either by using the
   included "bind_navl_externals" code fragment for your platform, or by
   specifying your own function bindings.
   IMPORTANT: navl_open will fail if any of these functions are not set.
*/

#ifndef NAVL_LIBRARY

#include <stddef.h>


/* structure definitions */
typedef int64_t navl_time_t;

struct navl_timeval
{
	long int tv_sec;
	long int tv_usec;
};

struct navl_tm
{ 
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
	char *tm_zone;
	int tm_gmtoff;
};

/* memory allocation */
extern void *(*navl_malloc_local)(size_t size);
extern void (*navl_free_local)(void *ptr);
extern void *(*navl_malloc_shared)(size_t size);
extern void (*navl_free_shared)(void *ptr);

/* ctype */
extern int (*navl_islower)(int c);
extern int (*navl_isupper)(int c);
extern int (*navl_tolower)(int c);
extern int (*navl_toupper)(int c);
extern int (*navl_isalnum)(int c);
extern int (*navl_isspace)(int c);
extern int (*navl_isdigit)(int c);

/* string functions */
extern int (*navl_atoi)(const char *nptr);
extern void *(*navl_memcpy)(void *dest, const void *src, size_t n);
extern int (*navl_memcmp)(const void *s1, const void *s2, size_t n);
extern void *(*navl_memset)(void *s, int c, size_t n);
extern int (*navl_strcasecmp)(const char *s1, const char *s2);
extern const char *(*navl_strchr)(const char *s, int c);
extern const char *(*navl_strrchr)(const char *s, int c);
extern int (*navl_strcmp)(const char *s1, const char *s2);
extern int (*navl_strncmp)(const char *s1, const char *s2, size_t n);
extern char *(*navl_strcpy)(char *dest, const char *src);
extern char *(*navl_strncpy)(char *dest, const char *src, size_t n);
extern char *(*navl_strerror)(int errnum);
extern size_t (*navl_strftime)(char *s, size_t max, const char *format, const struct navl_tm *tm);
extern size_t (*navl_strlen)(const char *s);
extern const char *(*navl_strpbrk)(const char *s, const char *accept);
extern const char *(*navl_strstr)(const char *haystack, const char *needle);
extern long int (*navl_strtol)(const char *nptr, char **endptr, int base);

/* input/output */
extern int (*navl_printf)(const char *format, ...);
extern int (*navl_sprintf)(char *str, const char *format, ...);
extern int (*navl_snprintf)(char *str, size_t size, const char *format, ...);
extern int (*navl_sscanf)(const char *str, const char *format, ...);
extern int (*navl_putchar)(int c);
extern int (*navl_puts)(const char *s);
extern int (*navl_diag_printf)(const char *format, ...);

/* time */
extern int (*navl_gettimeofday)(struct navl_timeval *tv, void *tz);
extern navl_time_t (*navl_mktime)(struct navl_tm *tm);

/* math */
extern double (*navl_log)(double x);
extern double (*navl_fabs)(double x);

/* system */
extern void (*navl_abort)(void);
extern unsigned long (*navl_get_thread_id)(void);

/* navl specific */
extern int (*navl_log_message)(const char *level, const char *func, const char *format, ... );

#endif /* NAVL_LIBRARY */

#ifdef __cplusplus
}
#endif

#endif /* NAVL_H */
