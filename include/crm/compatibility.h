/*
 * Copyright (C) 2012 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CRM_COMPATIBILITY__H
#  define CRM_COMPATIBILITY__H
#  define LOG_DEBUG_2  LOG_TRACE
#  define LOG_DEBUG_3  LOG_TRACE
#  define LOG_DEBUG_4  LOG_TRACE
#  define LOG_DEBUG_5  LOG_TRACE
#  define LOG_DEBUG_6  LOG_TRACE

#  define XML_CIB_ATTR_HASTATE         "ha"
#  define XML_CIB_ATTR_JOINSTATE       XML_NODE_JOIN_STATE
#  define XML_CIB_ATTR_EXPSTATE        XML_NODE_EXPECTED
#  define XML_CIB_ATTR_INCCM           XML_NODE_IN_CLUSTER
#  define XML_CIB_ATTR_CRMDSTATE       XML_NODE_IS_PEER

#  define CRMD_STATE_ACTIVE            CRMD_JOINSTATE_MEMBER
#  define CRMD_STATE_INACTIVE          CRMD_JOINSTATE_DOWN

/* *INDENT-OFF* */
enum cib_errors {
    cib_ok			=  pcmk_ok,
    cib_operation		= -EINVAL,
    cib_create_msg		= -EPROTO,
    cib_not_connected           = -ENOTCONN,
    cib_not_authorized          = -EACCES,
    cib_send_failed		= -ECOMM,
    cib_reply_failed            = -ENOMSG,
    cib_return_code		= -EPROTO,
    cib_output_data		= -ENOMSG,
    cib_connection		= -ENOTCONN,
    cib_authentication  	= -EPROTO,
    cib_missing 		= -EINVAL,
    cib_variant                 = -EPROTONOSUPPORT,
    CIBRES_MISSING_FIELD	= -EINVAL,
    cib_unknown                 = -EINVAL,
    cib_STALE                   = -ENOKEY,
    cib_EXISTS                  = -ENOTUNIQ,
    cib_NOTEXISTS		= -ENXIO,
    cib_ACTIVATION		= -ENODATA,
    cib_NOOBJECT		= -EINVAL,
    cib_NOPARENT		= -EINVAL,
    cib_NOTSUPPORTED            = -EPROTONOSUPPORT,
    cib_registration_msg	= -EPROTO,
    cib_callback_token          = -EPROTO,
    cib_callback_register	= -ECOMM,
    cib_client_gone		= -ECONNRESET,
    cib_not_master		= -EPERM,
    cib_missing_data            = -EINVAL,
    cib_remote_timeout          = -ETIME,
    cib_no_quorum		= -pcmk_err_no_quorum,
    cib_diff_failed		= -pcmk_err_diff_failed,
    cib_diff_resync		= -pcmk_err_diff_resync,
    cib_old_data		= -pcmk_err_old_data,
    cib_dtd_validation  	= -pcmk_err_dtd_validation,
    cib_bad_section		= -EINVAL,
    cib_bad_permissions         = -EACCES,
    cib_invalid_argument	= -EINVAL,
    cib_transform_failed        = -pcmk_err_transform_failed,
    cib_permission_denied	= -EACCES,
};

enum stonith_errors {
    stonith_ok			=  pcmk_ok,
    stonith_pending		= -EINPROGRESS,
    st_err_generic		= -pcmk_err_generic,
    st_err_internal		= -EPROTO,
    st_err_not_supported	= -EPROTONOSUPPORT,
    st_err_connection		= -ENOTCONN,
    st_err_missing		= -EINVAL,
    st_err_exists		= -ENOTUNIQ,
    st_err_timeout		= -ETIME,
    st_err_ipc			= -ECOMM,
    st_err_peer			= -ENOMSG,
    st_err_unknown_operation	= -EOPNOTSUPP,
    st_err_unknown_device	= -ENODEV,
    st_err_none_available	= -EHOSTUNREACH,
    st_err_signal		= -ECONNABORTED,
    st_err_agent_fork		= -ECHILD,
    st_err_agent_args		= -EREMOTEIO,
    st_err_agent		= -ECONNABORTED,
    st_err_invalid_level	= -EINVAL,
};


enum lrmd_errors {
    lrmd_ok                      =  pcmk_ok,
    lrmd_pending                 = -EINPROGRESS,
    lrmd_err_generic             = -EPROTONOSUPPORT,
    lrmd_err_internal            = -EPROTO,
    lrmd_err_connection          = -ENOTCONN,
    lrmd_err_missing             = -EINVAL,
    lrmd_err_ipc                 = -ECOMM,
    lrmd_err_peer                = -ENOMSG,
    lrmd_err_unknown_operation   = -EOPNOTSUPP,
    lrmd_err_unknown_rsc         = -ENODEV,
    lrmd_err_no_metadata         = -EIO,
    lrmd_err_stonith_connection  = -EUNATCH,
    lrmd_err_provider_required   = -EINVAL,
};
/* *INDENT-ON* */

#  define stonith_error2string pcmk_strerror
#  define lrmd_error2string    pcmk_strerror
#  define cib_error2string     pcmk_strerror

static inline void
slist_basic_destroy(GListPtr list)
{
    GListPtr gIter = NULL;

    for (gIter = list; gIter != NULL; gIter = gIter->next) {
        free(gIter->data);
    }
    g_list_free(list);
}

#  define crm_strdup strdup
#  define set_bit_inplace set_bit
#  define clear_bit_inplace clear_bit

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

#  define crm_free(free_obj) do { free(free_obj); free_obj=NULL; } while(0)

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

#  define xml_prop_iter(parent, prop_name, prop_value, code) do {	\
	if(parent != NULL) {						\
	    xmlAttrPtr prop_iter = parent->properties;			\
	    const char *prop_name = NULL;				\
	    const char *prop_value = NULL;				\
	    while(prop_iter != NULL) {					\
		prop_name = (const char *)prop_iter->name;		\
		prop_value = crm_element_value(parent, prop_name);	\
		prop_iter = prop_iter->next;				\
		if(prop_name) {						\
		    code;						\
		}							\
	    }								\
	}								\
    } while(0)

#  define xml_prop_name_iter(parent, prop_name, code) do {		\
	if(parent != NULL) {						\
	    xmlAttrPtr prop_iter = parent->properties;			\
	    const char *prop_name = NULL;				\
	    while(prop_iter != NULL) {					\
		prop_name = (const char *)prop_iter->name;		\
		prop_iter = prop_iter->next;				\
		if(prop_name) {						\
		    code;						\
		}							\
	    }								\
	}								\
    } while(0)

#  define zap_xml_from_parent(parent, xml_obj) free_xml(xml_obj); xml_obj = NULL

/* For ABI compatability with version < 1.1.4 */
static inline char *
calculate_xml_digest(xmlNode * input, gboolean sort, gboolean do_filter)
{
    return calculate_xml_digest_v1(input, sort, do_filter);
}

static inline void
free_xml_from_parent(xmlNode * parent, xmlNode * a_node)
{
    free_xml(a_node);
}

/* Use something like this instead of the next macro:

    GListPtr gIter = rsc->children;
    for(; gIter != NULL; gIter = gIter->next) {
	resource_t *child_rsc = (resource_t*)gIter->data;
	...
    }
 */
#  define slist_destroy(child_type, child, parent, a) do {		\
	GListPtr __crm_iter_head = parent;				\
	child_type *child = NULL;					\
	while(__crm_iter_head != NULL) {				\
	    child = (child_type *) __crm_iter_head->data;		\
	    __crm_iter_head = __crm_iter_head->next;			\
	    { a; }							\
	}								\
	g_list_free(parent);						\
    } while(0)

#  ifdef CRM_ATTRD__H
static inline gboolean
attrd_update(crm_ipc_t * cluster, char command, const char *host, const char *name,
             const char *value, const char *section, const char *set, const char *dampen)
{
    return attrd_update_delegate(cluster, command, host, name, value, section, set, dampen,
                                 NULL, FALSE) > 0;
}

static inline gboolean
attrd_lazy_update(char command, const char *host, const char *name,
                  const char *value, const char *section, const char *set, const char *dampen)
{
    return attrd_update_delegate(NULL, command, host, name, value, section, set, dampen, NULL, FALSE) > 0;
}

static inline gboolean
attrd_update_no_mainloop(int *connection, char command, const char *host,
                         const char *name, const char *value, const char *section,
                         const char *set, const char *dampen)
{
    return attrd_update_delegate(NULL, command, host, name, value, section, set, dampen, NULL, FALSE) > 0;
}
#  endif

#  ifdef CIB_UTIL__H
static inline int
update_attr(cib_t * the_cib, int call_options,
            const char *section, const char *node_uuid, const char *set_type, const char *set_name,
            const char *attr_id, const char *attr_name, const char *attr_value, gboolean to_console)
{
    return update_attr_delegate(the_cib, call_options, section, node_uuid, set_type, set_name,
                                attr_id, attr_name, attr_value, to_console, NULL);
}

static inline int
find_nvpair_attr(cib_t * the_cib, const char *attr, const char *section, const char *node_uuid,
                 const char *set_type, const char *set_name, const char *attr_id,
                 const char *attr_name, gboolean to_console, char **value)
{
    return find_nvpair_attr_delegate(the_cib, attr, section, node_uuid, set_type,
                                     set_name, attr_id, attr_name, to_console, value, NULL);
}

static inline int
read_attr(cib_t * the_cib,
          const char *section, const char *node_uuid, const char *set_type, const char *set_name,
          const char *attr_id, const char *attr_name, char **attr_value, gboolean to_console)
{
    return read_attr_delegate(the_cib, section, node_uuid, set_type, set_name,
                              attr_id, attr_name, attr_value, to_console, NULL);
}

static inline int
delete_attr(cib_t * the_cib, int options,
            const char *section, const char *node_uuid, const char *set_type, const char *set_name,
            const char *attr_id, const char *attr_name, const char *attr_value, gboolean to_console)
{
    return delete_attr_delegate(the_cib, options, section, node_uuid, set_type, set_name,
                                attr_id, attr_name, attr_value, to_console, NULL);
}

static inline void
log_cib_diff(int log_level, xmlNode * diff, const char *function)
{
    xml_log_patchset(log_level, function, diff);
}

static inline gboolean
apply_cib_diff(xmlNode * old, xmlNode * diff, xmlNode ** new)
{
    *new = copy_xml(old);
    return (xml_apply_patchset(*new, diff, TRUE) == pcmk_ok);
}

#  endif

#  ifdef CRM_COMMON_XML__H
void
log_xml_diff(uint8_t log_level, xmlNode * diff, const char *function)
{
    xml_log_patchset(log_level, function, diff);
}
#  endif

#endif
