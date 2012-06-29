#define cib_ok				 0
#define lrmd_ok                      	 0
#define stonith_ok			 0
#define st_err_generic			-1001
#define cib_no_quorum			-1002
#define cib_dtd_validation		-1003
#define cib_transform_failed		-1004
#define cib_bad_permissions		-EACCES
#define cib_not_authorized		-EACCES
#define cib_permission_denied		-EACCES
#define st_err_agent_fork		-ECHILD
#define cib_callback_register		-ECOMM
#define cib_send_failed			-ECOMM
#define lrmd_err_ipc                 	-ECOMM
#define st_err_ipc			-ECOMM
#define st_err_agent			-ECONNABORTED
#define st_err_signal			-ECONNABORTED
#define cib_client_gone			-ECONNRESET
#define st_err_none_available		-EHOSTUNREACH
#define lrmd_pending                 	-EINPROGRESS
#define stonith_pending			-EINPROGRESS
#define cib_bad_section			-EINVAL
#define cib_invalid_argument		-EINVAL
#define cib_missing_data		-EINVAL
#define cib_missing			-EINVAL
#define cib_NOOBJECT			-EINVAL
#define cib_NOPARENT			-EINVAL
#define cib_operation			-EINVAL
#define CIBRES_MISSING_FIELD		-EINVAL
#define cib_unknown			-EINVAL
#define lrmd_err_missing             	-EINVAL
#define lrmd_err_provider_required   	-EINVAL
#define st_err_invalid_level		-EINVAL
#define st_err_missing			-EINVAL
#define lrmd_err_no_metadata         	-EIO
#define cib_old_data			-EKEYEXPIRED
#define cib_diff_failed			-EKEYREJECTED
#define cib_diff_resync			-EL2NSYNC
#define cib_ACTIVATION			-ENODATA
#define lrmd_err_unknown_rsc         	-ENODEV
#define st_err_unknown_device		-ENODEV
#define cib_STALE			-ENOKEY
#define cib_output_data			-ENOMSG
#define cib_reply_failed		-ENOMSG
#define lrmd_err_peer                	-ENOMSG
#define st_err_peer			-ENOMSG
#define cib_connection			-ENOTCONN
#define cib_not_connected		-ENOTCONN
#define lrmd_err_connection          	-ENOTCONN
#define st_err_connection		-ENOTCONN
#define cib_EXISTS			-ENOTUNIQ
#define st_err_exists			-ENOTUNIQ
#define cib_NOTEXISTS			-ENXIO
#define lrmd_err_unknown_operation   	-EOPNOTSUPP
#define st_err_unknown_operation	-EOPNOTSUPP
#define cib_not_master			-EPERM
#define cib_authentication		-EPROTO
#define cib_callback_token		-EPROTO
#define cib_create_msg			-EPROTO
#define cib_registration_msg		-EPROTO
#define cib_return_code			-EPROTO
#define lrmd_err_internal            	-EPROTO
#define st_err_internal			-EPROTO
#define cib_NOTSUPPORTED		-EPROTONOSUPPORT
#define cib_variant			-EPROTONOSUPPORT
#define lrmd_err_generic             	-EPROTONOSUPPORT
#define st_err_not_supported		-EPROTONOSUPPORT
#define st_err_agent_args		-EREMOTEIO
#define cib_remote_timeout		-ETIME
#define st_err_timeout			-ETIME
#define lrmd_err_stonith_connection  	-EUNATCH

static inline void
slist_basic_destroy(GListPtr list)
{
    GListPtr gIter = NULL;

    for (gIter = list; gIter != NULL; gIter = gIter->next) {
        free(gIter->data);
    }
    g_list_free(list);
}

#  define crm_malloc0(malloc_obj, length) do {				\
	malloc_obj = malloc(length);					\
	if(malloc_obj == NULL) {					\
	    crm_err("Failed allocation of %lu bytes", (unsigned long)length); \
	    CRM_ASSERT(malloc_obj != NULL);				\
	}								\
	memset(malloc_obj, 0, length);					\
    } while(0)

#  define crm_malloc(malloc_obj, length) do {				\
	malloc_obj = malloc(length);					\
	if(malloc_obj == NULL) {					\
	    crm_err("Failed allocation of %lu bytes", (unsigned long)length); \
	    CRM_ASSERT(malloc_obj != NULL);				\
	}								\
    } while(0)

#  define crm_realloc(realloc_obj, length) do {				\
	realloc_obj = realloc(realloc_obj, length);			\
	CRM_ASSERT(realloc_obj != NULL);				\
    } while(0)

#define crm_free(free_obj) do { free(free_obj); free_obj=NULL; } while(0)

/* These two child iterator macros are no longer to be used
 * They exist for compatability reasons and will be removed in a
 * future release
 */
#  define xml_child_iter(parent, child, code) do {			\
	if(parent != NULL) {						\
		xmlNode *child = NULL;					\
		xmlNode *__crm_xml_iter = parent->children;		\
		while(__crm_xml_iter != NULL) {				\
			child = __crm_xml_iter;				\
			__crm_xml_iter = __crm_xml_iter->next;		\
			if(child->type == XML_ELEMENT_NODE) {		\
			    code;					\
			}						\
		}							\
	}								\
    } while(0)

#  define xml_child_iter_filter(parent, child, filter, code) do {	\
	if(parent != NULL) {						\
	    xmlNode *child = NULL;					\
	    xmlNode *__crm_xml_iter = parent->children;			\
	    while(__crm_xml_iter != NULL) {				\
		child = __crm_xml_iter;					\
		__crm_xml_iter = __crm_xml_iter->next;			\
		if(child->type == XML_ELEMENT_NODE) {			\
		    if(filter == NULL					\
		       || crm_str_eq(filter, (const char *)child->name, TRUE)) { \
			code;						\
		    }							\
		}							\
	    }								\
	}								\
    } while(0)
