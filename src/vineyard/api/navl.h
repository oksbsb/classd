#ifndef NAVL_H
#define NAVL_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#ifdef _WINDOWS
#ifdef NAVL_LIBRARY
#define NAVL_API __declspec(dllexport)
#else
#define NAVL_API __declspec(dllimport)
#endif
#else
#ifdef NAVL_LIBRARY
#define NAVL_API __attribute__ ((visibility("default")))
#else
#define NAVL_API
#endif
#endif


/*******************************************************************************
 * Types and constants
 ******************************************************************************/

typedef enum {
	NAVL_STATE_TERMINATED = 0,  /* Indicates the connection has been terminated */
	NAVL_STATE_INSPECTING = 1,  /* Indicates the connection is under inspection */
	NAVL_STATE_MONITORING = 2,  /* Indicates the connection is under monitoring */
	NAVL_STATE_CLASSIFIED = 3   /* Indicates the connection is fully classified */
} navl_state_t;

typedef enum {
	NAVL_ENCAP_NONE = 0,     /* When no layer 2-4 transport headers are present */
	NAVL_ENCAP_ETH  = 1,     /* Buffer under inspection starts at Ethernet header */
	NAVL_ENCAP_IP   = 2,     /* Buffer under inspection starts at IPv4 header */
	NAVL_ENCAP_IP6  = 3,     /* Buffer under inspection starts at IPv6 header */
	NAVL_ENCAP_MPLS = 4      /* Buffer under inspection starts at MPLS header */
} navl_encap_t;

#define NAVL_AF_UNSPEC  0
#define NAVL_AF_INET    1
#define NAVL_AF_INET6   2

typedef struct navl_host {
	unsigned char  family;          /* NAVL_AF_INET or NAVL_AF_INET6 */
	unsigned char  padding;
	unsigned short port;            /* Layer 4 port in network order */
	union {
		unsigned int  in4_addr;     /* IPv4 address in network order */
		unsigned char in6_addr[16]; /* IPv6 address in network order */
	};
} navl_host_t;

enum {
	/* Context is available in the most significant 16 bits */
	NAVL_ATTR_F_CTXMASK  = 0xFFFF0000,

	/* Flag bits are available in the least significant 16 bits */
	NAVL_ATTR_F_BITMASK  = 0x0000FFFF,
	NAVL_ATTR_F_FRAGMENT = (1 << 0)
};

enum {
	/* As a policy, controls whether these features are enabled for a given
	 * instance. As a status, indicates the current features applied to the
	 * connection. */
	NAVL_CONN_F_DPI        = (1 << 0),
	NAVL_CONN_F_MUTABLE    = (1 << 1),
	NAVL_CONN_F_FUTUREFLOW = (1 << 2),
	NAVL_CONN_F_ATTRIBUTE  = (1 << 3),
	NAVL_CONN_F_TUNNELING  = (1 << 4)
};

typedef enum {
	NAVL_NOTIFY_ALL = 0,     /* Notification for all events */
	NAVL_NOTIFY_EDGE = 1     /* Additional notifications are suppressed until
	                          * all outstanding events are handled */
} navl_notification_level_t;

typedef enum {
	NAVL_INITIATOR_SIDE = 0,   /* Current packet is from initiator side */
	NAVL_RECIPIENT_SIDE = 1    /* Current packet is from recipient side */
} navl_packet_side_t;

typedef struct
{
   uint64_t software_flags;
   uint8_t productivity;
   uint8_t risk;
   uint16_t category_total;
   uint16_t categories[32];
} navl_guid_properties_t;

typedef void *navl_iterator_t;
typedef void *navl_result_t;
typedef int navl_handle_t;
typedef void *navl_conn_t;
typedef uint64_t navl_conn_id_t;
typedef uint32_t navl_conn_flags_t;


/*******************************************************************************
 * Library instance and thread initialization
 ******************************************************************************/

/*
 * navl_open()
 *
 * Opens a new navl instance and registers the available classification plugins.
 * On success, a handle for the instance is returned. On error, -1 is returned.
 */
NAVL_API navl_handle_t navl_open(const char *plugins);

/*
 * navl_init()
 *
 * Initializes a thread for the handle.
 * On success, 0 is returned. On error, -1 is returned.
 */
NAVL_API int navl_init(navl_handle_t handle);

/*
 * navl_fini()
 *
 * Finalize a thread for the handle.
 * On success, 0 is returned. On error, -1 is returned.
 */
NAVL_API int navl_fini(navl_handle_t handle);

/*
 * navl_close()
 * 
 * Closes the navl instance referenced by @handle.
 * On success, 0 is returned. On error, -1 is returned. 
 */
NAVL_API int navl_close(navl_handle_t handle);


/*******************************************************************************
 * Classification APIs 
 ******************************************************************************/

/* 
 * navl_classify_simple()
 *
 * Simple classification API.
 * On success, 0 is returned and the best classification result is available in
 * @index. On error, -1 is returned.
 */
NAVL_API int navl_classify_simple(navl_handle_t handle, const void *data, unsigned short len, int *index);

/* 
 * navl_classify()
 *
 * Main classification API
 * On success, the user callback is invoked and 0 is returned. On error, -1 is 
 * returned.
 *
 * Notes:
 *
 * The classify_callback signature includes an error parameter. Errors reported
 * in the callback are not considered critical, but provide an indication when
 * results may have been compromised.
 */

typedef int (*navl_classify_callback_t)(navl_handle_t handle, navl_result_t result, navl_state_t state
	, navl_conn_t conn, void *arg, int error);

NAVL_API int navl_classify(navl_handle_t handle, navl_encap_t encap, const void *data, unsigned short len
	, navl_conn_t conn, int direction, navl_classify_callback_t, void *arg);


/*******************************************************************************
 * Result processing
 ******************************************************************************/

/* 
 * navl_conn_id_get()
 *
 * Returns the connection identifier assigned to this navl_conn_t. 
 *
 * Note: 
 *
 * A connection identifier is unique per instance. This API should never fail;
 * however, a connection identifier with a value of 0 (zero) indicates that navl
 * is not tracking the connection and any result data applies only to the current
 * packet under inspection.
 */
NAVL_API navl_conn_id_t navl_conn_id_get(navl_handle_t handle, navl_conn_t conn);

/*
 * navl_conn_packet_side_get()
 *
 * On success, 0 is returned and @side is filled in accordingly.
 * @side is NAVL_INITIATOR_SIDE if current packet is from initiator side.
 * @side is NAVL_RECIPIENT_SIDE if current packet is from recipient side.
 *
 * On error, -1 is returned.
 */
NAVL_API int navl_conn_packet_side_get(navl_conn_t conn, navl_packet_side_t *side);

/*
 * navl_endpoint_get()
 *
 * Provides the endpoint information for the connection. The results always reflect
 * the direction of the packet under inspection.
 *
 * On success, 0 is returned and @src and @dst are filled in accordingly. 
 * On error, -1 is returned.
 */
NAVL_API int navl_endpoint_get(navl_handle_t handle, navl_conn_t conn, navl_host_t *src, navl_host_t *dst);

/*
 * navl_conn_endpoint_get()
 *
 * Provides the endpoint information for the connection. The results always reflect
 * the direction with respect to the connection initiator.
 *
 * On success, 0 is returned and @src, @dst, and @proto are filled in accordingly.
 * On error, -1 is returned.
 */

NAVL_API int navl_conn_endpoint_get(navl_handle_t handle, navl_conn_t conn, navl_host_t *src, navl_host_t *dst, unsigned char *proto);

/*
 * Callback signature for navl_futureflow_callback_set()
 *
 * @src         the initiator host info
 * @dst         the recipient host info
 * @proto       the ip protocol
 * @parent_id   the app id of the flow expecting the futureflow
 * @child_id    the app id of the future flow
 *
 */ 
typedef void (*navl_futureflow_callback_t)(navl_handle_t, navl_host_t *src, navl_host_t *dst, unsigned char proto, int parent_id, int child_id); 

/*
 * navl_futureflow_callback_set()
 * 
 * DEPRECATION WARNING:
 * This functionality will be removed in a future release. The information is
 * now available through protocol-specific attributes.
 *
 * Bind a futureflow handler for the given instance.
 *
 * On sucess, 0 is returned. On error, -1 is returned.
 */
NAVL_API int navl_futureflow_callback_set(navl_handle_t, navl_futureflow_callback_t);

/*
 * navl_app_get()
 *
 * On success, returns the application protocol index for the result and sets a
 * confidence value in @confidence. On error, -1 is returned.
 */
NAVL_API int navl_app_get(navl_handle_t handle, navl_result_t result, int *confidence);

/*
 * navl_history_app_get
 * Get previous classification result for the result along with its confidence level.
 *
 * returns the application protocol index (integer > 0) and confidence level from previous classification result
 * returns -1 if there aren't any previous result available
 */
NAVL_API int navl_history_app_get(navl_handle_t handle, navl_result_t result, int *confidence);

/*
 * navl_history_proto_first
 *
 * Returns the first iterator in previous classification result:
 * The iterator is used to navigate through the protocol stack just like it is done for
 * the latest classification result stack.
 */
NAVL_API navl_iterator_t navl_history_proto_first(navl_handle_t handle, navl_result_t result);

/*
 * navl_history_proto_valid()
 *
 * Returns 1 if the iterator is valid.
 */
NAVL_API int navl_history_proto_valid(navl_handle_t handle, navl_iterator_t it);

/*
 * navl_history_proto_next()
 *
 * Returns the next iterator.
 */
NAVL_API navl_iterator_t navl_history_proto_next(navl_handle_t handle, navl_iterator_t it);


/*
 * navl_history_proto_get_index()
 *
 * Extracts the protocol from the iterator.
 */
NAVL_API int navl_history_proto_get_index(navl_handle_t handle, navl_iterator_t it);

/*
 * navl_proto_first()
 *
 * Returns the first iterator in the result.
 */
NAVL_API navl_iterator_t navl_proto_first(navl_handle_t handle, navl_result_t result);

/* 
 * navl_proto_valid()
 *
 * Returns 1 if the iterator is valid.
 */
NAVL_API int navl_proto_valid(navl_handle_t handle, navl_iterator_t it);

/*
 * navl_proto_next()
 *
 * Returns the next iterator.
 */
NAVL_API navl_iterator_t navl_proto_next(navl_handle_t handle, navl_iterator_t it);

/*
 * navl_proto_prev()
 *
 * Returns the prev iterator.
 */
NAVL_API navl_iterator_t navl_proto_prev(navl_handle_t handle, navl_iterator_t it);

/*
 * navl_proto_top()
 *
 * Returns an iterator pointing to the top most protocol.
 */
NAVL_API navl_iterator_t navl_proto_top(navl_handle_t handle, navl_result_t result);

/*
 * navl_proto_find()
 *
 * Returns an iterator pointing to the protocol @index.
 */
NAVL_API navl_iterator_t navl_proto_find(navl_handle_t handle, navl_result_t result, int index);

/*
 * navl_proto_get_index()
 *
 * Extracts the protocol from the iterator.
 */
NAVL_API int navl_proto_get_index(navl_handle_t handle, navl_iterator_t it);

/*
 * navl_proto_find_index()
 *
 * Extracts the protocol from the short name.
 */
NAVL_API int navl_proto_find_index(navl_handle_t handle, const char *name);

/*
 * navl_proto_get_properties()
 *
 * On success, return 0 and return navl_guid_properties_t in @prop_t. On error, return -1.
 */
NAVL_API int navl_proto_get_properties(navl_handle_t handle, int index, navl_guid_properties_t *prop_t);

/*
 * navl_proto_is_defunct()
 *
 * On success, return 1 if the protocol with given index is defunct, otherwise 0. On error, return -1.
 */
NAVL_API int navl_proto_is_defunct(navl_handle_t handle, int index);

/*
 * navl_proto_get_name()
 *
 * Returns a pointer to the proto name/
 */
NAVL_API const char *navl_proto_get_name(navl_handle_t handle, int index, char *buf, unsigned int size);


/*******************************************************************************
 * Connection information
 ******************************************************************************/

/*
 * navl_conn_user_set()
 *
 * Set opaque data in the navl_conn_t.
 *
 * On success, return 0. On error, return -1.
 */
NAVL_API int navl_conn_user_set(navl_handle_t handle, navl_conn_t conn, void *user_data);

/*
 * navl_conn_user_get()
 *
 * Get opaque data in the navl_conn_t.
 *
 * On success, return 0 and return data in @user_data. On error, return -1.
 */
NAVL_API int navl_conn_user_get(navl_handle_t handle, navl_conn_t conn, void **user_data);

/*
 * navl_conn_status_flags_get()
 *
 * Fetch the connection flags enabled for @conn.
 *
 * On success, return 0. On error, returns -1.
 */
NAVL_API int navl_conn_status_flags_get(navl_handle_t handle, navl_conn_t conn, navl_conn_flags_t *flags);

/*
 * navl_conn_policy_flags_disable()
 *
 * Clear the specific policy flags for @conn. 
 *
 * On success, return 0, On error, return -1.
 */
NAVL_API int navl_conn_policy_flags_disable(navl_handle_t handle, navl_conn_t conn, navl_conn_flags_t flags);


/*******************************************************************************
 * Connection management (IPv4 and IPv6)
 ******************************************************************************/

/*
 * navl_conn_create()
 *
 * Allocate connection state by 5-tuple.
 *
 * On success, 0 is returned and opaque state is attached to @conn. On error, 
 * -1 is returned.
 *
 * Note:
 *
 * The integrator MUST ensure they pair each successful call to navl_conn_create()
 * with a call to navl_conn_destroy(). This ensure navl can release all associated 
 * resources.
 */
NAVL_API int navl_conn_create(navl_handle_t handle, navl_host_t *shost, navl_host_t *dhost, unsigned char proto, navl_conn_t *conn);

/*
 * navl_conn_lookup()
 *
 * Lookup a connection state by 5-tuple.
 *
 * On success, 0 is returned and opaque state is attached to @conn. On error, 
 * -1 is returned.
 */
NAVL_API int navl_conn_lookup(navl_handle_t handle, navl_host_t *shost, navl_host_t *dhost, unsigned char proto, navl_conn_t *conn);

/*
 * navl_conn_destroy()
 *
 * Releases connection state previously allocated by navl_conn_create().
 *
 * On success, 0 is returned. On error, -1 is returned. 
 */
NAVL_API int navl_conn_destroy(navl_handle_t handle, navl_conn_t conn);

/*******************************************************************************
 * Protocol/Index Management
 ******************************************************************************/

/*
 * navl_proto_max_index()
 *
 * Returns the max protocol index.
 */
NAVL_API int navl_proto_max_index(navl_handle_t handle);

/*
 * navl_proto_set_index()
 *
 * Set the GUID protocol string @name to the value @index.
 *
 * On success, returns 0. On error, returns -1.
 */
NAVL_API int navl_proto_set_index(navl_handle_t handle, const char *name, int index);


/*******************************************************************************
 * Sync Event Management
 ******************************************************************************/

/*
* navl_syncevent_get()
*
* On success, returns 0, and the buffer @data of size @len will be filled with
* the oldest outstanding synchronization event, with @len set to the amount of
* data written. If no more events are ready, @len will be set to zero.
* On failure, returns -1. If @len was not sufficient to hold the event, @len is
* set to the required size.
*
* Note:
*
* No combination of the sync event management functions may be called
* simultaneously. Each can be called from any thread, but thread-safety MUST be
* guaranteed by the integrator.
*/
NAVL_API int navl_syncevent_get(navl_handle_t h, void *data, unsigned short *len);

/*
* navl_syncevent_callback
*
* This provides the callback signature that the publisher (i.e. the sender)
* needs to implement if they want to be notified of synchronized events. This
* is called when a new synchronized event is ready to be read by the user.
*/
typedef void (*navl_syncevent_callback_t)(navl_handle_t h, void *arg);

/*
* navl_syncevent_callback_set()
*
* Set the callback to subscribe to synchronized events. The user callback will
* be invoked for synchronized events with frequency dependent on the
* notification level.
*
* On success, returns 0. On failure -1.
*/
NAVL_API int navl_syncevent_callback_set(navl_handle_t h, navl_syncevent_callback_t callback
	, navl_notification_level_t level);

/*
* navl_syncevent_push()
*
* Pushed a received sync event to the navl instance specified by @handle.
*
* On success, return 0. On failure -1.
*
* Note: Although synchronized events are typically published by classification
* threads, a non-classification thread (one that has not called navl_init())
* may push events to a running instance.
*/
NAVL_API int navl_syncevent_push(navl_handle_t h, const void *data, unsigned short len);


/*******************************************************************************
 * Attribute Management
 ******************************************************************************/

/* Callback signature for navl attributes */ 
typedef void (*navl_attr_callback_t)(navl_handle_t, navl_conn_t conn, int attr_type, int attr_length, const void *attr_value
	, int attr_flag, void *);

/*
 * navl_attr_callback_set()
 *
 * Returns 0 on success or -1 if the attribute was not found.
 */
NAVL_API int navl_attr_callback_set(navl_handle_t handle, const char *attr, navl_attr_callback_t callback);

/*
 * navl_attr_key_get()
 *
 * Returns the attribute key on success or -1 on if the attribute was not found. 
 */
NAVL_API int navl_attr_key_get(navl_handle_t handle, const char *attr);

/*
 * navl_attr_offset_get()
 *
 * Returns the offset into the @data passed to navl_classify for this attribute or -1 if the value is not within @data.
 */
NAVL_API int navl_attr_offset_get(navl_handle_t handle, const void *attr_value);

/*******************************************************************************
 * Configuration
 ******************************************************************************/
/*
 * navl_suppress_ld_errors()
 *
 * Enables/disables reporting errors on third party library loading (1 - to suppress, 0 - to allow)
 * Has no effect if called after navl_open
 *
 */
NAVL_API void navl_suppress_ld_errors(int enable_ld_errors);
/*
 * navl_config_set()
 *
 * Directly set a configuration variable - use with caution!
 *
 * On success, returns 0. On error, returns -1.
 */
NAVL_API int navl_config_set(navl_handle_t handle, const char *key, const char *val);

/*
 * navl_config_get()
 *
 * Get a configuration variable.
 *
 * On success, returns 0. On error, returns -1.
 */
NAVL_API int navl_config_get(navl_handle_t handle, const char *key, char *val, int size);

/*
 * navl_config_dump_verbose()
 *
 * Dumps the entire configuration via navl_diag_printf.
 * On success, returns 0. On error, returns -1.
 *
 * Note in order to use this you must bind navl_diag_printf to a valid callback
 * function.
 */
NAVL_API int navl_config_dump_verbose(navl_handle_t handle);

/*
 * navl_config_dump()
 *
 * Dumps only configuration which has been modified through navl_config_set.
 * On success, returns 0. On error, returns -1.
 */
NAVL_API int navl_config_dump(navl_handle_t handle);


/*******************************************************************************
 * Clock Manipulation
 ******************************************************************************/

/*
 * navl_clock_set_mode()
 *
 * Set and unset the clock mode:
 * 
 * 0 = auto, navl will use the system clock via the external function
 * navl_gettimeofday(). This is the default setting.
 *
 * 1 = manual, navl will use the time from the value set by navl_clock_set().
 */
NAVL_API void navl_clock_set_mode(navl_handle_t handle, int value);

/*
 * navl_clock_set()
 *
 * Manually set the wallclock time.
 */
NAVL_API void navl_clock_set(navl_handle_t handle, int64_t msecs);


/*******************************************************************************
 * Custom Protocols and Rules
 ******************************************************************************/

/*
 * navl_proto_add()
 *
 * Create and register a custom protocol with the given string name @protoname 
 * and a requested protocol @index (or zero for auto-assign). 
 *
 * On success, returns protocol index. On error, returns -1.
 */
NAVL_API int navl_proto_add(navl_handle_t handle, const char *protoname, int index);

/*
 * navl_proto_remove()
 *
 * Removes a custom protocol with the given @protoname.
 *
 * On success, 0 is returned. On error, returns -1.
 */
NAVL_API int navl_proto_remove(navl_handle_t handle, const char *protoname);

/*
 * navl_rule_add()
 *
 * Bind a protocol to a rule. See navl api guide for details.
 *
 * On success, 0 is returned. On error, returns -1.
 */
NAVL_API int navl_rule_add(navl_handle_t handle, int index, const char *module, const char *rule);

/*
 * navl_rule_remove()
 *
 * Unbind a protocol from a rule.
 *
 * On success, 0 is returned. On error, returns -1.
 */
NAVL_API int navl_rule_remove(navl_handle_t handle, int index, const char *module, const char *rule);


/*******************************************************************************
 * Runtime Utility Functions
 ******************************************************************************/

/*
 * navl_error_get()
 *
 * Returns the current value of the thread/instance-specific error.
 */
NAVL_API int navl_error_get(navl_handle_t handle);

/*
 * navl_idle()
 *
 * Perform necessary maintenance on idle thread. This should be called at
 * least once per second if thread is not calling navl_classify().
 *
 */
NAVL_API void navl_idle(navl_handle_t handle);

/*
 * navl_handle_get()
 *
 * Returns the navl instance handle active on the current thread. This may
 * may be used inside external functions to determine the active instance.
 *
 * Returns 0 on a thread for which navl_init has not been called.
 */
NAVL_API navl_handle_t navl_handle_get(void);

/*
 * navl_diag()
 *
 * Write diagnostic information for a module via navl_diag_printf.
 *
 * On success, 0 is returned. On error, returns -1.
 */
NAVL_API int navl_diag(navl_handle_t handle, const char *module, const char *args);

/*
 * navl_memory_tag_get()
 *
 * Returns the current memory tags associated with this thread. The lower 16
 * bits contains a context (ctx) index/tag and the upper 16 bit contain an
 * object (obj) index/tag.
 */ 
NAVL_API int navl_memory_tag_get(navl_handle_t);

/*
 * navl_memory_ctx_num()
 *
 * Returns the number of memory context identifiers.
 */
NAVL_API int navl_memory_ctx_num(navl_handle_t);

/*
 * navl_memory_ctx_name()
 *
 * Converts a context index retrived by navl_memory_tag_get() into a readable
 * string.
 *
 * On success, 0 is returned. On error, returns -1.
 */
NAVL_API int navl_memory_ctx_name(navl_handle_t, int, char *, int);

/*
 * navl_memory_obj_num()
 *
 * Returns the number of memory object identifiers.
 */
NAVL_API int navl_memory_obj_num(navl_handle_t);

/*
 * navl_memory_obj_name()
 *
 * Converts an object index retrived by navl_memory_tag_get() into a readablei
 * string.
 *
 * On success, 0 is returned. On error, returns -1.
 */
NAVL_API int navl_memory_obj_name(navl_handle_t, int, char *, int);

/* 6-tuple API
 *
 */
/* Signature for navl_tuple_vlan_callback_set and navl_tuple_mpls_callback_set
 * @stack_length is the stack size in bytes
 * @stack_top - an address of first byte of most outer tag/label
 * @parsed_entry - an address where VLAN tag/MPLS lavel to use is written
 * returned VLAN tag/MPLS header must be in host order format that is:
 * for VLAN TPID - 2 bits, user priority - 3 bits, CFI - 1 bit, VLAN ID - 12 bits
 * for MPLS header: label number - 20 bits, exp bits - 3 bits, bs - 1 bit, ttl - 8 bits
 * @arg - argument provided on navl_classify call
 */
typedef void (*navl_tuple_callback_t)(navl_handle_t, navl_conn_t conn, int stack_length, const void *stack_top, uint32_t *parsed_entry
	, void *arg);

/*
 * navl_tuple_vlan_callback_set()
 *
 * sets a @callback on a packet if at least one vlan tag is present
 *
 * On success 0 is returned. On error returns -1
 */
NAVL_API int navl_tuple_vlan_callback_set(navl_handle_t handle, navl_tuple_callback_t callback);

/*
 * navl_tuple_mpls_callback_set()
 *
 * sets a @callback on a packet if at least one MPLS label is present
 *
 * On success 0 is returned. On error returns -1
 */
NAVL_API int navl_tuple_mpls_callback_set(navl_handle_t handle, navl_tuple_callback_t callback);
/* *****************************************************************************
 * End of 6-tuple API
 *******************************************************************************/


/*******************************************************************************
 * End of API declarations
 *******************************************************************************/


/* 
 * The following section contains declarations of NAVL external functions. These
 * functions are required by NAVL but are not bound initially. You must bind these
 * function pointers to real functions either by using the included 
 * "bind_navl_externals" code fragment for your platform, or by specifying your own
 * function bindings.
 *
 * IMPORTANT: navl_open will fail if any of these functions are not set.
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
NAVL_API extern void *(*navl_malloc_local)(size_t size);
NAVL_API extern void (*navl_free_local)(void *ptr);
NAVL_API extern void *(*navl_malloc_shared)(size_t size);
NAVL_API extern void (*navl_free_shared)(void *ptr);

/* ctype */
NAVL_API extern int (*navl_islower)(int c);
NAVL_API extern int (*navl_isupper)(int c);
NAVL_API extern int (*navl_tolower)(int c);
NAVL_API extern int (*navl_toupper)(int c);
NAVL_API extern int (*navl_isalnum)(int c);
NAVL_API extern int (*navl_isspace)(int c);
NAVL_API extern int (*navl_isdigit)(int c);

/* string functions */
NAVL_API extern int (*navl_atoi)(const char *nptr);
NAVL_API extern void *(*navl_memcpy)(void *dest, const void *src, size_t n);
NAVL_API extern int (*navl_memcmp)(const void *s1, const void *s2, size_t n);
NAVL_API extern void *(*navl_memset)(void *s, int c, size_t n);
NAVL_API extern int (*navl_strcasecmp)(const char *s1, const char *s2);
NAVL_API extern const char *(*navl_strchr)(const char *s, int c);
NAVL_API extern const char *(*navl_strrchr)(const char *s, int c);
NAVL_API extern int (*navl_strcmp)(const char *s1, const char *s2);
NAVL_API extern int (*navl_strncmp)(const char *s1, const char *s2, size_t n);
NAVL_API extern char *(*navl_strcpy)(char *dest, const char *src);
NAVL_API extern char *(*navl_strncpy)(char *dest, const char *src, size_t n);
NAVL_API extern char *(*navl_strerror)(int errnum);
NAVL_API extern size_t (*navl_strftime)(char *s, size_t max, const char *format, const struct navl_tm *tm);
NAVL_API extern size_t (*navl_strlen)(const char *s);
NAVL_API extern const char *(*navl_strpbrk)(const char *s, const char *accept);
NAVL_API extern const char *(*navl_strstr)(const char *haystack, const char *needle);
NAVL_API extern long int (*navl_strtol)(const char *nptr, char **endptr, int base);

/* input/output */
NAVL_API extern int (*navl_printf)(const char *format, ...);
NAVL_API extern int (*navl_sprintf)(char *str, const char *format, ...);
NAVL_API extern int (*navl_snprintf)(char *str, size_t size, const char *format, ...);
NAVL_API extern int (*navl_sscanf)(const char *str, const char *format, ...);
NAVL_API extern int (*navl_putchar)(int c);
NAVL_API extern int (*navl_puts)(const char *s);
NAVL_API extern int (*navl_diag_printf)(const char *format, ...);

/* time */
NAVL_API extern int (*navl_gettimeofday)(struct navl_timeval *tv, void *tz);
NAVL_API extern navl_time_t (*navl_mktime)(struct navl_tm *tm);

/* math */
NAVL_API extern double (*navl_log)(double x);
NAVL_API extern double (*navl_fabs)(double x);

/* system */
NAVL_API extern void (*navl_abort)(void);
NAVL_API extern unsigned long (*navl_get_thread_id)(void);

/* navl specific */
NAVL_API extern int (*navl_log_message)(const char *level, const char *func, const char *format, ... );

#endif /* NAVL_LIBRARY */

#ifdef __cplusplus
}
#endif

#endif /* NAVL_H */
