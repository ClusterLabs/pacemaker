
/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>
#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <libxml/xmlreader.h>

#if HAVE_BZLIB_H
#  include <bzlib.h>
#endif

#if HAVE_LIBXML2
#  include <libxml/parser.h>
#  include <libxml/tree.h>
#  include <libxml/relaxng.h>
#endif

#if HAVE_LIBXSLT
#  include <libxslt/xslt.h>
#  include <libxslt/transform.h>
#endif

#define XML_BUFFER_SIZE	4096
#define XML_PARSER_DEBUG 0
#define BEST_EFFORT_STATUS 0

void
xml_log(int priority, const char *fmt, ...)
G_GNUC_PRINTF(2, 3);
static inline int
__get_prefix(const char *prefix, xmlNode *xml, char *buffer, int offset);

void
xml_log(int priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    qb_log_from_external_source_va(__FUNCTION__, __FILE__, fmt, priority, __LINE__, 0, ap);
    va_end(ap);
}

typedef struct {
    xmlRelaxNGPtr rng;
    xmlRelaxNGValidCtxtPtr valid;
    xmlRelaxNGParserCtxtPtr parser;
} relaxng_ctx_cache_t;

struct schema_s {
    int type;
    const char *name;
    const char *location;
    const char *transform;
    int after_transform;
    void *cache;
};

typedef struct {
    int found;
    const char *string;
} filter_t;

enum xml_private_flags {
     xpf_none      = 0x000,
     xpf_dirty     = 0x001,
     xpf_deleted   = 0x002,
     xpf_created   = 0x004,

     xpf_tracking  = 0x010,
     xpf_processed = 0x020,
     xpf_skip      = 0x040,
     xpf_moved     = 0x080,
};

typedef struct xml_private_s 
{
        long check;
        uint32_t flags;
        GListPtr deleted_paths;
} xml_private_t;

/* *INDENT-OFF* */

struct schema_s known_schemas[] = {
    /* 0 */    { 0, NULL, NULL, NULL, 1 },
    /* 1 */    { 1, "pacemaker-0.6",    "crm.dtd",		"upgrade06.xsl", 4, NULL },
    /* 2 */    { 1, "transitional-0.6", "crm-transitional.dtd",	"upgrade06.xsl", 4, NULL },
    /* 3 */    { 2, "pacemaker-0.7",    "pacemaker-1.0.rng",	NULL, 0, NULL },
    /* 4 */    { 2, "pacemaker-1.0",    "pacemaker-1.0.rng",	NULL, 6, NULL },
    /* 5 */    { 2, "pacemaker-1.1",    "pacemaker-1.1.rng",	NULL, 6, NULL },
    /* 6 */    { 2, "pacemaker-1.2",    "pacemaker-1.2.rng",	NULL, 0, NULL },
    /* 7 */    { 0, "none", NULL, NULL, 0, NULL },
};

static filter_t filter[] = {
    { 0, XML_ATTR_ORIGIN },
    { 0, XML_CIB_ATTR_WRITTEN },
    { 0, XML_ATTR_UPDATE_ORIG },
    { 0, XML_ATTR_UPDATE_CLIENT },
    { 0, XML_ATTR_UPDATE_USER },
};
/* *INDENT-ON* */

static int all_schemas = DIMOF(known_schemas);
static int max_schemas = DIMOF(known_schemas) - 2;      /* skip back past 'none' */
static xmlNode *subtract_xml_comment(xmlNode * parent, xmlNode * left, xmlNode * right, gboolean * changed);
static xmlNode *find_xml_comment(xmlNode * root, xmlNode * search_comment);
static int add_xml_comment(xmlNode * parent, xmlNode * target, xmlNode * update);

#define CHUNK_SIZE 1024
#define TRACKING_CHANGES(xml) xml->doc?is_set(((xml_private_t *)xml->doc->_private)->flags, xpf_tracking):FALSE

#define buffer_print(buffer, max, offset, fmt, args...) do {            \
        int rc = (max);                                                 \
        if(buffer) {                                                    \
            rc = snprintf((buffer) + (offset), (max) - (offset), fmt, ##args); \
        }                                                               \
        if(rc < 0) {                                                    \
            crm_perror(LOG_ERR, "snprintf failed");                     \
            (buffer)[(offset)] = 0;                                     \
            return;                                                     \
        } else if(rc >= ((max) - (offset))) {                           \
            (max) = QB_MAX(CHUNK_SIZE, (max) * 2);                             \
            (buffer) = realloc((buffer), (max) + 1);                    \
        } else {                                                        \
            offset += rc;                                               \
            break;                                                      \
        }                                                               \
    } while(1);

static void
insert_prefix(int options, char **buffer, int *offset, int *max, int depth)
{
    if (options & xml_log_option_formatted) {
        size_t spaces = 2 * depth;

        if ((*buffer) == NULL || spaces >= ((*max) - (*offset))) {
            (*max) = QB_MAX(CHUNK_SIZE, (*max) * 2);
            (*buffer) = realloc((*buffer), (*max) + 1);
        }
        memset((*buffer) + (*offset), ' ', spaces);
        (*offset) += spaces;
    }
}

static char *
get_schema_path(const char *file)
{
    static const char *base = NULL;

    if (base == NULL) {
        base = getenv("PCMK_schema_directory");
    }
    if (base == NULL || strlen(base) == 0) {
        base = CRM_DTD_DIRECTORY;
    }
    return crm_concat(base, file, '/');
}

static void
set_parent_flag(xmlNode *xml, long flag) 
{

    for(; xml; xml = xml->parent) {
        xml_private_t *p = xml->_private;

        if(p == NULL) {
            /* During calls to xmlDocCopyNode(), _private will be unset for parent nodes */
        } else {
            p->flags |= flag;
            /* crm_trace("Setting flag %x due to %s[@id=%s]", flag, xml->name, ID(xml)); */
        }
    }
}

static void
set_doc_flag(xmlNode *xml, long flag) 
{

    if(xml && xml->doc && xml->doc->_private){
        /* During calls to xmlDocCopyNode(), xml->doc may be unset */
        xml_private_t *p = xml->doc->_private;

        p->flags |= flag;
        /* crm_trace("Setting flag %x due to %s[@id=%s]", flag, xml->name, ID(xml)); */
    }
}

static void
crm_node_dirty(xmlNode *xml) 
{
    set_doc_flag(xml, xpf_dirty);
    set_parent_flag(xml, xpf_dirty);
}

static void
crm_node_created(xmlNode *xml) 
{
    xmlNode *cIter = NULL;
    xml_private_t *p = xml->_private;

    if(p && TRACKING_CHANGES(xml)) {
        if(is_not_set(p->flags, xpf_created)) {
            p->flags |= xpf_created;
            crm_node_dirty(xml);
        }

        for (cIter = __xml_first_child(xml); cIter != NULL; cIter = __xml_next(cIter)) {
           crm_node_created(cIter);
        }
    }
}

static void
crm_attr_dirty(xmlAttr *a) 
{
    xmlNode *parent = a->parent;
    xml_private_t *p = NULL;

    p = a->_private;
    p->flags |= xpf_dirty;
    p->flags = (p->flags & ~xpf_deleted);
    /* crm_trace("Setting flag %x due to %s[@id=%s, @%s=%s]", */
    /*           xpf_dirty, parent?parent->name:NULL, ID(parent), a->name, a->children->content); */

    crm_node_dirty(parent);
}

int get_tag_name(const char *input, size_t offset, size_t max);
int get_attr_name(const char *input, size_t offset, size_t max);
int get_attr_value(const char *input, size_t offset, size_t max);
gboolean can_prune_leaf(xmlNode * xml_node);

void diff_filter_context(int context, int upper_bound, int lower_bound,
                         xmlNode * xml_node, xmlNode * parent);
int in_upper_context(int depth, int context, xmlNode * xml_node);
int add_xml_object(xmlNode * parent, xmlNode * target, xmlNode * update, gboolean as_diff);

static inline const char *
crm_attr_value(xmlAttr * attr)
{
    if (attr == NULL || attr->children == NULL) {
        return NULL;
    }
    return (const char *)attr->children->content;
}

static inline xmlAttr *
crm_first_attr(xmlNode * xml)
{
    if (xml == NULL) {
        return NULL;
    }
    return xml->properties;
}

static void
pcmkRegisterNode(xmlNodePtr node)
{
    xml_private_t *p = NULL;

    /* TODO: Comment nodes? */
    switch(node->type) {
        case XML_ELEMENT_NODE:
        case XML_DOCUMENT_NODE:
        case XML_ATTRIBUTE_NODE:
            p = calloc(1, sizeof(xml_private_t));
            p->check = (long) 0x81726354;
            /* Flags will be reset if necessary when tracking is enabled */
            p->flags |= (xpf_dirty|xpf_created);
            node->_private = p;
            break;
        case XML_TEXT_NODE:
            break;
        default:
            /* Ignore */
            crm_trace("Ignoring %p %d", node, node->type);
            break;
    }

    if(p && TRACKING_CHANGES(node)) {
        /* XML_ELEMENT_NODE doesn't get picked up here, node->doc is
         * not hooked up at the point we are called
         */
        set_doc_flag(node, xpf_dirty);
        crm_node_dirty(node);
    }
}

static void
pcmkDeregisterNode(xmlNodePtr node)
{
    xml_private_t *p = node->_private;

    switch(node->type) {
        case XML_ELEMENT_NODE:
        case XML_DOCUMENT_NODE:
        case XML_ATTRIBUTE_NODE:
            CRM_ASSERT(node->_private != NULL);
            CRM_ASSERT(p->check == (long) 0x81726354);
            free(node->_private);
            break;
        default:
            break;
    }
}

void
xml_track_changes(xmlNode * xml) 
{
    xml_accept_changes(xml);
    crm_trace("Tracking changes to %p", xml);
    set_doc_flag(xml, xpf_tracking);
}

bool xml_tracking_changes(xmlNode * xml)
{
    if(xml == NULL) {
        return FALSE;

    } else if(is_set(((xml_private_t *)xml->doc->_private)->flags, xpf_tracking)) {
        return TRUE;
    }
    return FALSE;
}

bool xml_document_dirty(xmlNode *xml) 
{
    if(xml != NULL && xml->doc && xml->doc->_private) {
        xml_private_t *doc = xml->doc->_private;

        return is_set(doc->flags, xpf_dirty);
    }
    return FALSE;
}

/*
<diff format="2.0">
  <version>
    <source admin_epoch="1" epoch="2" num_updates="3"/>
    <target admin_epoch="1" epoch="3" num_updates="0"/>
  </version>
  <change operation="add" xpath="/cib/configuration/nodes">
    <node id="node2" uname="node2" description="foo"/>
  </change>
  <change operation="add" xpath="/cib/configuration/nodes/node[node2]">
    <instance_attributes id="nodes-node"><!-- NOTE: can be a full tree -->
      <nvpair id="nodes-node2-ram" name="ram" value="1024M"/>
    </instance_attributes>
  </change>
  <change operation="update" xpath="/cib/configuration/nodes[@id='node2']">
    <change-list>
      <change-attr operation="set" name="type" value="member"/>
      <change-attr operation="unset" name="description"/>
    </change-list>
    <change-result>
      <node id="node2" uname="node2" type="member"/><!-- NOTE: not recursive -->
    </change-result>
  </change>
  <change operation="delete" xpath="/cib/configuration/nodes/node[@id='node3'] /">
  <change operation="update" xpath="/cib/configuration/resources/group[@id='g1']">
    <change-list>
      <change-attr operation="set" name="description" value="some grabage here"/>
    </change-list>
    <change-result>
      <group id="g1" description="some grabage here"/><!-- NOTE: not recursive -->
    </change-result>
  </change>
  <change operation="update" xpath="/cib/status/node_state[@id='node2]/lrm[@id='node2']/lrm_resources/lrm_resource[@id='Fence']">
    <change-list>
      <change-attr operation="set" name="oper" value="member"/>
      <change-attr operation="set" name="operation_key" value="Fence_start_0"/>
      <change-attr operation="set" name="operation" value="start"/>
      <change-attr operation="set" name="transition-key" value="2:-1:0:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"/>
      <change-attr operation="set" name="transition-magic" value="0:0;2:-1:0:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"/>
      <change-attr operation="set" name="call-id" value="2"/>
      <change-attr operation="set" name="rc-code" value="0"/>
    </change-list>
    <change-result>
      <lrm_rsc_op id="Fence_last_0" operation_key="Fence_start_0" operation="start" crm-debug-origin="crm_simulate"  transition-key="2:-1:0:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" transition-magic="0:0;2:-1:0:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" call-id="2" rc-code="0" op-status="0" interval="0" exec-time="0" queue-time="0" op-digest="f2317cad3d54cec5d7d7aa7d0bf35cf8"/>
    </change-result>
  </change>
</diff>
 */
static int __xml_offset(xmlNode *xml) 
{
    int position = 0;
    xmlNode *cIter = NULL;

    for(cIter = xml; cIter->prev; cIter = cIter->prev) {
        xml_private_t *p = cIter->_private;

        if(is_not_set(p->flags, xpf_skip)) {
            position++;
        }
    }

    return position;
}

static void
__xml_build_changes(xmlNode * xml, xmlNode *patchset)
{
    xmlNode *cIter = NULL;
    xmlAttr *pIter = NULL;
    xmlNode *change = NULL;
    xml_private_t *p = xml->_private;

    if(patchset && is_set(p->flags, xpf_created)) {
        int offset = 0;
        char buffer[XML_BUFFER_SIZE];

        if(__get_prefix(NULL, xml->parent, buffer, offset) > 0) {
            int position = __xml_offset(xml);

            change = create_xml_node(patchset, XML_DIFF_CHANGE);

            crm_xml_add(change, XML_DIFF_OP, "create");
            crm_xml_add(change, XML_DIFF_PATH, buffer);
            crm_xml_add_int(change, XML_DIFF_POSITION, position);
            add_node_copy(change, xml);
        }

        return;
    }

    for (pIter = crm_first_attr(xml); pIter != NULL; pIter = pIter->next) {
        xmlNode *attr = NULL;

        p = pIter->_private;
        if(is_not_set(p->flags, xpf_deleted) && is_not_set(p->flags, xpf_dirty)) {
            continue;
        }

        if(change == NULL) {
            int offset = 0;
            char buffer[XML_BUFFER_SIZE];

            if(__get_prefix(NULL, xml, buffer, offset) > 0) {
                change = create_xml_node(patchset, XML_DIFF_CHANGE);

                crm_xml_add(change, XML_DIFF_OP, "modify");
                crm_xml_add(change, XML_DIFF_PATH, buffer);

                change = create_xml_node(change, XML_DIFF_LIST);
            }
        }

        attr = create_xml_node(change, XML_DIFF_ATTR);

        crm_xml_add(attr, XML_NVPAIR_ATTR_NAME, (const char *)pIter->name);
        if(p->flags & xpf_deleted) {
            crm_xml_add(attr, XML_DIFF_OP, "unset");

        } else {
            const char *value = crm_element_value(xml, (const char *)pIter->name);

            crm_xml_add(attr, XML_DIFF_OP, "set");
            crm_xml_add(attr, XML_NVPAIR_ATTR_VALUE, value);
        }
    }

    if(change) {
        xmlNode *result = NULL;

        change = create_xml_node(change->parent, XML_DIFF_RESULT);
        result = create_xml_node(change, (const char *)xml->name);

        for (pIter = crm_first_attr(xml); pIter != NULL; pIter = pIter->next) {
            const char *value = crm_element_value(xml, (const char *)pIter->name);

            crm_xml_add(result, (const char *)pIter->name, value);
        }
    }

    for (cIter = __xml_first_child(xml); cIter != NULL; cIter = __xml_next(cIter)) {
        __xml_build_changes(cIter, patchset);
    }

    p = xml->_private;
    if(patchset && is_set(p->flags, xpf_moved)) {
        int offset = 0;
        char buffer[XML_BUFFER_SIZE];

        crm_trace("%s.%s moved to position %d", xml->name, ID(xml), __xml_offset(xml));
        if(__get_prefix(NULL, xml, buffer, offset) > 0) {
            change = create_xml_node(patchset, XML_DIFF_CHANGE);

            crm_xml_add(change, XML_DIFF_OP, "move");
            crm_xml_add(change, XML_DIFF_PATH, buffer);
            crm_xml_add_int(change, XML_DIFF_POSITION, __xml_offset(xml));
        }
    }
}

static void
__xml_accept_changes(xmlNode * xml)
{
    xmlNode *cIter = NULL;
    xmlAttr *pIter = NULL;
    xml_private_t *p = xml->_private;

    p->flags = xpf_none;

    for (pIter = crm_first_attr(xml); pIter != NULL; pIter = pIter->next) {
        p = pIter->_private;
        if(p->flags & xpf_deleted) {
            xml_remove_prop(xml, (const char *)pIter->name);

        } else {
            p->flags = xpf_none;
        }
    }

    for (cIter = __xml_first_child(xml); cIter != NULL; cIter = __xml_next(cIter)) {
        __xml_accept_changes(cIter);
    }
}

static bool
is_config_change(xmlNode *xml)
{
    GListPtr gIter = NULL;
    xml_private_t *p = NULL;
    xmlNode *config = first_named_child(xml, XML_CIB_TAG_CONFIGURATION);

    if(config) {
        p = config->_private;
    }
    if(p && is_set(p->flags, xpf_dirty)) {
        return TRUE;
    }

    if(xml->doc && xml->doc->_private) {
        p = xml->doc->_private;
        for(gIter = p->deleted_paths; gIter; gIter = gIter->next) {
            char *path = gIter->data;

            if(strstr(path, "/"XML_TAG_CIB"/"XML_CIB_TAG_CONFIGURATION) != NULL) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

static void
xml_repair_v1_diff(xmlNode * last, xmlNode * next, xmlNode * local_diff, gboolean changed)
{
    int lpc = 0;
    xmlNode *cib = NULL;
    xmlNode *diff_child = NULL;

    const char *tag = NULL;

    const char *vfields[] = {
        XML_ATTR_GENERATION_ADMIN,
        XML_ATTR_GENERATION,
        XML_ATTR_NUMUPDATES,
    };

    if (local_diff == NULL) {
        crm_trace("Nothing to do");
        return;
    }

    tag = "diff-removed";
    diff_child = find_xml_node(local_diff, tag, FALSE);
    if (diff_child == NULL) {
        diff_child = create_xml_node(local_diff, tag);
    }

    tag = XML_TAG_CIB;
    cib = find_xml_node(diff_child, tag, FALSE);
    if (cib == NULL) {
        cib = create_xml_node(diff_child, tag);
    }

    for(lpc = 0; last && lpc < DIMOF(vfields); lpc++){
        const char *value = crm_element_value(last, vfields[lpc]);

        crm_xml_add(diff_child, vfields[lpc], value);
        if(changed || lpc == 2) {
            crm_xml_add(cib, vfields[lpc], value);
        }
    }

    tag = "diff-added";
    diff_child = find_xml_node(local_diff, tag, FALSE);
    if (diff_child == NULL) {
        diff_child = create_xml_node(local_diff, tag);
    }

    tag = XML_TAG_CIB;
    cib = find_xml_node(diff_child, tag, FALSE);
    if (cib == NULL) {
        cib = create_xml_node(diff_child, tag);
    }

    for(lpc = 0; next && lpc < DIMOF(vfields); lpc++){
        const char *value = crm_element_value(next, vfields[lpc]);

        crm_xml_add(diff_child, vfields[lpc], value);
    }

    if (next) {
        xmlAttrPtr xIter = NULL;

        for (xIter = next->properties; xIter; xIter = xIter->next) {
            const char *p_name = (const char *)xIter->name;
            const char *p_value = crm_element_value(next, p_name);

            xmlSetProp(cib, (const xmlChar *)p_name, (const xmlChar *)p_value);
        }
    }

    crm_log_xml_explicit(local_diff, "Repaired-diff");
}

static xmlNode *
xml_create_patchset_v1(xmlNode *source, xmlNode *target, bool config)
{
    xmlNode *patchset = diff_xml_object(source, target, TRUE);

    if(patchset) {
        CRM_LOG_ASSERT(xml_document_dirty(target));
        xml_repair_v1_diff(source, target, patchset, config);
        crm_xml_add(patchset, "format", "1");
    }
    return patchset;
}

static xmlNode *
xml_create_patchset_v2(xmlNode *source, xmlNode *target)
{
    int lpc = 0;
    GListPtr gIter = NULL;
    xml_private_t *doc = NULL;

    xmlNode *v = NULL;
    xmlNode *version = NULL;
    xmlNode *patchset = NULL;
    const char *vfields[] = {
        XML_ATTR_GENERATION_ADMIN,
        XML_ATTR_GENERATION,
        XML_ATTR_NUMUPDATES,
    };

    CRM_ASSERT(target);
    if(xml_document_dirty(target) == FALSE) {
        return NULL;
    }

    CRM_ASSERT(target->doc);
    doc = target->doc->_private;

    patchset = create_xml_node(NULL, XML_TAG_DIFF);
    crm_xml_add_int(patchset, "format", 2);

    version = create_xml_node(patchset, XML_DIFF_VERSION);

    v = create_xml_node(version, XML_DIFF_VSOURCE);
    for(lpc = 0; lpc < DIMOF(vfields); lpc++){
        const char *value = crm_element_value(source, vfields[lpc]);

        if(value == NULL) {
            value = "1";
        }
        crm_xml_add(v, vfields[lpc], value);
    }

    v = create_xml_node(version, XML_DIFF_VTARGET);
    for(lpc = 0; lpc < DIMOF(vfields); lpc++){
        const char *value = crm_element_value(target, vfields[lpc]);

        if(value == NULL) {
            value = "1";
        }
        crm_xml_add(v, vfields[lpc], value);
    }

    for(gIter = doc->deleted_paths; gIter; gIter = gIter->next) {
        xmlNode *change = create_xml_node(patchset, XML_DIFF_CHANGE);

        crm_xml_add(change, XML_DIFF_OP, "delete");
        crm_xml_add(change, XML_DIFF_PATH, gIter->data);
    }

    __xml_build_changes(target, patchset);
    return patchset;
}

static gboolean patch_legacy_mode(void)
{
    static gboolean init = TRUE;
    static gboolean legacy = FALSE;

    if(init) {
        init = FALSE;
        legacy = daemon_option_enabled("legacy", "cib");
        if(legacy) {
            crm_notice("Enabled legacy mode");
        }
    }
    return legacy;
}

xmlNode *
xml_create_patchset(int format, xmlNode *source, xmlNode *target, bool *config_changed, bool manage_version, bool with_digest)
{
    int counter = 0;
    bool config = FALSE;
    xmlNode *patch = NULL;
    const char *version = crm_element_value(source, XML_ATTR_CRM_VERSION);

    if(xml_document_dirty(target) == FALSE) {
        crm_trace("No change %d", format);
        return NULL; /* No change */
    }

    config = is_config_change(target);
    if(config_changed) {
        *config_changed = config;
    }

    if(manage_version && config) {
        crm_trace("Config changed %d", format);
        crm_xml_add(target, XML_ATTR_NUMUPDATES, "0");

        crm_element_value_int(target, XML_ATTR_GENERATION, &counter);
        crm_xml_add_int(target, XML_ATTR_GENERATION, counter+1);

    } else if(manage_version) {
        crm_trace("Status changed %d", format);
        crm_element_value_int(target, XML_ATTR_NUMUPDATES, &counter);
        crm_xml_add_int(target, XML_ATTR_NUMUPDATES, counter+1);
    }

    if(format == 0) {
        if(patch_legacy_mode()) {
            format = 1;

        } else if(compare_version("3.0.8", version) < 0) {
            format = 2;

        } else {
            format = 1;
        }
        crm_trace("Using patch format %d for version: %s", format, version);
    }

    switch(format) {
        case 1:
            patch = xml_create_patchset_v1(source, target, config);
            with_digest = TRUE;
            break;
        case 2:
            patch = xml_create_patchset_v2(source, target);
            break;
        default:
            crm_err("Unknown patch format: %d", format);
            return NULL;
    }

    if(patch && with_digest) {
        const char *digest = calculate_xml_versioned_digest(target, FALSE, TRUE, version);

        crm_xml_add(patch, XML_ATTR_DIGEST, digest);
    }
    return patch;
}

void
xml_log_patchset(uint8_t log_level, const char *function, xmlNode * patchset)
{
    int format = 1;
    xmlNode *child = NULL;
    xmlNode *added = NULL;
    xmlNode *removed = NULL;
    gboolean is_first = TRUE;

    int add[3];
    int del[3];

    const char *fmt = NULL;
    const char *digest = NULL;
    int options = xml_log_option_formatted;

    static struct qb_log_callsite *patchset_cs = NULL;

    if (patchset_cs == NULL) {
        patchset_cs = qb_log_callsite_get(function, __FILE__, "xml-patchset", log_level, __LINE__, 0);
    }

    if (patchset == NULL) {
        crm_trace("Empty patch");
        return;

    } else if (crm_is_callsite_active(patchset_cs, log_level, 0) == FALSE) {
        return;
    }

    xml_patch_versions(patchset, add, del);
    fmt = crm_element_value(patchset, "format");
    digest = crm_element_value(patchset, XML_ATTR_DIGEST);

    if (add[2] != del[2] || add[1] != del[1] || add[0] != del[0]) {
        do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                         "Diff: --- %d.%d.%d %s", del[0], del[1], del[2], fmt);
        do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                         "Diff: +++ %d.%d.%d %s", add[0], add[1], add[2], digest);

    } else if (patchset != NULL && (add[0] || add[1] || add[2])) {
        do_crm_log(log_level,
                   "%s: Local-only Change: %d.%d.%d", function ? function : "",
                   add[0], add[1], add[2]);
    }

    crm_element_value_int(patchset, "format", &format);
    if(format == 2) {
        xml_log_changes(log_level, function, patchset);
        return;
    }

    if (log_level < LOG_DEBUG || function == NULL) {
        options |= xml_log_option_diff_short;
    }

    removed = find_xml_node(patchset, "diff-removed", FALSE);
    for (child = __xml_first_child(removed); child != NULL; child = __xml_next(child)) {
        log_data_element(log_level, __FILE__, function, __LINE__, "- ", child, 0,
                         options | xml_log_option_diff_minus);
        if (is_first) {
            is_first = FALSE;
        } else {
            do_crm_log(log_level, " --- ");
        }
    }

    is_first = TRUE;
    added = find_xml_node(patchset, "diff-added", FALSE);
    for (child = __xml_first_child(added); child != NULL; child = __xml_next(child)) {
        log_data_element(log_level, __FILE__, function, __LINE__, "+ ", child, 0,
                         options | xml_log_option_diff_plus);
        if (is_first) {
            is_first = FALSE;
        } else {
            do_crm_log(log_level, " +++ ");
        }
    }
}

void
xml_log_changes(uint8_t log_level, const char *function, xmlNode * xml)
{
    GListPtr gIter = NULL;
    xml_private_t *doc = NULL;

    CRM_ASSERT(xml);
    CRM_ASSERT(xml->doc);

    doc = xml->doc->_private;
    if(is_not_set(doc->flags, xpf_dirty)) {
        return;
    }

    for(gIter = doc->deleted_paths; gIter; gIter = gIter->next) {
        do_crm_log(log_level, "-- %s", gIter->data);
    }

    log_data_element(log_level, __FILE__, function, __LINE__, "- ", xml, 0,
                     xml_log_option_formatted|xml_log_option_dirty_del);

    log_data_element(log_level, __FILE__, function, __LINE__, "+ ", xml, 0,
                     xml_log_option_formatted|xml_log_option_dirty_add);
}

void
xml_accept_changes(xmlNode * xml)
{
    xmlNode *top = NULL;
    xml_private_t *doc = NULL;

    if(xml == NULL) {
        return;
    }

    crm_trace("Accepting changes to %p", xml);
    doc = xml->doc->_private;
    top = xmlDocGetRootElement(xml->doc);

    doc->flags = (doc->flags & ~xpf_tracking);

    if(is_not_set(doc->flags, xpf_dirty)) {
        return;
    }

    __xml_accept_changes(top);
    doc->flags = (doc->flags & ~xpf_dirty);

    g_list_free_full(doc->deleted_paths, free);
    doc->deleted_paths = NULL;
}

/* Simplified version for applying v1-style XML patches */
static void
__subtract_xml_object(xmlNode * target, xmlNode * patch)
{
    xmlNode *patch_child = NULL;
    xmlNode *target_child = NULL;
    xmlAttrPtr xIter = NULL;

    char *id = NULL;
    const char *name = NULL;
    const char *value = NULL;

    if (target == NULL || patch == NULL) {
        return;
    }

    if (target->type == XML_COMMENT_NODE) {
        gboolean dummy;

        subtract_xml_comment(target->parent, target, patch, &dummy);
    }

    name = crm_element_name(target);
    CRM_CHECK(name != NULL, return);
    CRM_CHECK(safe_str_eq(crm_element_name(target), crm_element_name(patch)), return);
    CRM_CHECK(safe_str_eq(ID(target), ID(patch)), return);

    /* check for XML_DIFF_MARKER in a child */
    id = crm_element_value_copy(target, XML_ATTR_ID);
    value = crm_element_value(patch, XML_DIFF_MARKER);
    if (value != NULL && strcmp(value, "removed:top") == 0) {
        crm_trace("We are the root of the deletion: %s.id=%s", name, id);
        free_xml(target);
        free(id);
        return;
    }

    for (xIter = crm_first_attr(patch); xIter != NULL; xIter = xIter->next) {
        const char *p_name = (const char *)xIter->name;

        xml_remove_prop(target, p_name);
    }
    /* Restore the id field, it is never allowed to change */
    crm_xml_add(target, XML_ATTR_ID, id);

    /* changes to child objects */
    for (target_child = __xml_first_child(target); target_child != NULL;
         target_child = __xml_next(target_child)) {

        if (target_child->type == XML_COMMENT_NODE) {
            patch_child = find_xml_comment(patch, target_child);

        } else {
            patch_child = find_entity(patch, crm_element_name(target_child), ID(target_child));
        }

        __subtract_xml_object(target_child, patch_child);
    }
    free(id);
}

static void
__add_xml_object(xmlNode * parent, xmlNode * target, xmlNode * patch)
{
    xmlNode *patch_child = NULL;
    xmlNode *target_child = NULL;
    xmlAttrPtr xIter = NULL;

    const char *id = NULL;
    const char *name = NULL;
    const char *value = NULL;

    if (patch == NULL) {
        return;
    } else if (parent == NULL && target == NULL) {
        return;
    }

    /* check for XML_DIFF_MARKER in a child */
    value = crm_element_value(patch, XML_DIFF_MARKER);
    if (target == NULL
        && value != NULL
        && strcmp(value, "added:top") == 0) {
        id = ID(patch);
        name = crm_element_name(patch);
        crm_trace("We are the root of the addition: %s.id=%s", name, id);
        add_node_copy(parent, patch);
        return;

    } else if(target == NULL) {
        id = ID(patch);
        name = crm_element_name(patch);
        crm_err("Could not locate: %s.id=%s", name, id);
        return;
    }

    if (target->type == XML_COMMENT_NODE) {
        add_xml_comment(parent, target, patch);
    }

    id = ID(target);
    name = crm_element_name(target);
    CRM_CHECK(name != NULL, return);
    CRM_CHECK(safe_str_eq(crm_element_name(target), crm_element_name(patch)), return);
    CRM_CHECK(safe_str_eq(ID(target), ID(patch)), return);

    for (xIter = crm_first_attr(patch); xIter != NULL; xIter = xIter->next) {
        const char *p_name = (const char *)xIter->name;
        const char *p_value = crm_element_value(patch, p_name);

        xml_remove_prop(target, p_name); /* Preserve the patch order */
        crm_xml_add(target, p_name, p_value);
    }

    /* changes to child objects */
    for (patch_child = __xml_first_child(patch); patch_child != NULL;
         patch_child = __xml_next(patch_child)) {

        if (patch_child->type == XML_COMMENT_NODE) {
            target_child = find_xml_comment(target, patch_child);

        } else {
            target_child = find_entity(target, crm_element_name(patch_child), ID(patch_child));
        }

        __add_xml_object(target, target_child, patch_child);
    }
}

bool xml_patch_versions(xmlNode *patchset, int add[3], int del[3])
{
    int lpc = 0;
    int format = 1;
    xmlNode *tmp = NULL;

    const char *vfields[] = {
        XML_ATTR_GENERATION_ADMIN,
        XML_ATTR_GENERATION,
        XML_ATTR_NUMUPDATES,
    };


    crm_element_value_int(patchset, "format", &format);
    switch(format) {
        case 1:
            tmp = find_xml_node(patchset, "diff-removed", FALSE);
            break;
        case 2:
            tmp = find_xml_node(patchset, "version", FALSE);
            tmp = find_xml_node(tmp, "source", FALSE);
            break;
        default:
            crm_warn("Unknown patch format: %d", format);
            return -EINVAL;
    }

    for(lpc = 0; lpc < DIMOF(vfields); lpc++) {
        crm_element_value_int(tmp, vfields[lpc], &(del[lpc]));
        crm_trace("Got %d for del[%s]", del[lpc], vfields[lpc]);
    }

    switch(format) {
        case 1:
            tmp = find_xml_node(patchset, "diff-added", FALSE);
            break;
        case 2:
            tmp = find_xml_node(patchset, "version", FALSE);
            tmp = find_xml_node(tmp, "target", FALSE);
            break;
        default:
            crm_warn("Unknown patch format: %d", format);
            return -EINVAL;
    }

    for(lpc = 0; lpc < DIMOF(vfields); lpc++) {
        crm_element_value_int(tmp, vfields[lpc], &(add[lpc]));
        crm_trace("Got %d for add[%s]", add[lpc], vfields[lpc]);
    }

    return pcmk_ok;
}

static int
xml_patch_version_check(xmlNode *xml, xmlNode *patchset, int format) 
{
    int lpc = 0;
    bool changed = FALSE;

    int this[] = { 0, 0, 0 };
    int add[] = { 0, 0, 0 };
    int del[] = { 0, 0, 0 };

    const char *vfields[] = {
        XML_ATTR_GENERATION_ADMIN,
        XML_ATTR_GENERATION,
        XML_ATTR_NUMUPDATES,
    };

    xmlNode *tmp = NULL;

    for(lpc = 0; lpc < DIMOF(vfields); lpc++) {
        crm_element_value_int(xml, vfields[lpc], &(this[lpc]));
        crm_trace("Got %d for this[%s]", this[lpc], vfields[lpc]);
        if (this[lpc] < 0) {
            this[lpc] = 0;
        }
    }

    switch(format) {
        case 1:
            tmp = find_xml_node(patchset, "diff-removed", FALSE);
            break;
        case 2:
            tmp = find_xml_node(patchset, "version", FALSE);
            tmp = find_xml_node(tmp, "source", FALSE);
            break;
        default:
            crm_warn("Unknown patch format: %d", format);
            return -EINVAL;
    }

    for(lpc = 0; lpc < DIMOF(vfields); lpc++) {
        crm_element_value_int(tmp, vfields[lpc], &(del[lpc]));
        crm_trace("Got %d for del[%s]", del[lpc], vfields[lpc]);
    }

    switch(format) {
        case 1:
            tmp = find_xml_node(patchset, "diff-added", FALSE);
            break;
        case 2:
            tmp = find_xml_node(patchset, "version", FALSE);
            tmp = find_xml_node(tmp, "target", FALSE);
            break;
        default:
            crm_warn("Unknown patch format: %d", format);
            return -EINVAL;
    }

    for(lpc = 0; lpc < DIMOF(vfields); lpc++) {
        crm_element_value_int(tmp, vfields[lpc], &(add[lpc]));
        crm_trace("Got %d for add[%s]", add[lpc], vfields[lpc]);
    }

    if(add[0] == -1 && add[1] == -1 && add[2] == -1) {
        add[0] = this[0];
        add[1] = this[1];
        add[2] = this[2] + 1;
        for(lpc = 0; lpc < DIMOF(vfields); lpc++) {
            del[lpc] = this[lpc];
        }
    }

    for(lpc = 0; lpc < DIMOF(vfields); lpc++) {
        if(this[lpc] < del[lpc]) {
            crm_info("Current %s is too low (%d < %d)", vfields[lpc], this[lpc], del[lpc]);
            return -pcmk_err_diff_resync;

        } else if(this[lpc] > del[lpc]) {
            crm_notice("Current %s is too high (%d > %d)", vfields[lpc], this[lpc], del[lpc]);
            return -pcmk_err_diff_failed;
        }
    }

    for(lpc = 0; lpc < DIMOF(vfields); lpc++) {
        if(add[lpc] > del[lpc]) {
            changed = TRUE;
        }
    }

    if(changed == FALSE) {
        crm_notice("Versions did not change in patch %d.%d.%d", add[0], add[1], add[2]);
        return -pcmk_err_diff_failed;
    }

    crm_info("Applying patch %d.%d.%d to %d.%d.%d",
             add[0], add[1], add[2], this[0], this[1], this[2]);
    return pcmk_ok;
}

static int
xml_apply_patchset_v1(xmlNode *xml, xmlNode *patchset, bool check_version) 
{
    int rc = pcmk_ok;
    int root_nodes_seen = 0;
    const char *digest = crm_element_value(patchset, XML_ATTR_DIGEST);
    char *version = crm_element_value_copy(xml, XML_ATTR_CRM_VERSION);

    xmlNode *child_diff = NULL;
    xmlNode *added = find_xml_node(patchset, "diff-added", FALSE);
    xmlNode *removed = find_xml_node(patchset, "diff-removed", FALSE);
    xmlNode *old = copy_xml(xml);

    crm_trace("Substraction Phase");
    for (child_diff = __xml_first_child(removed); child_diff != NULL;
         child_diff = __xml_next(child_diff)) {
        CRM_CHECK(root_nodes_seen == 0, rc = FALSE);
        if (root_nodes_seen == 0) {
            __subtract_xml_object(xml, child_diff);
        }
        root_nodes_seen++;
    }

    if (root_nodes_seen > 1) {
        crm_err("(-) Diffs cannot contain more than one change set... saw %d", root_nodes_seen);
        rc = -ENOTUNIQ;
    }

    root_nodes_seen = 0;
    crm_trace("Addition Phase");
    if (rc == pcmk_ok) {
        xmlNode *child_diff = NULL;

        for (child_diff = __xml_first_child(added); child_diff != NULL;
             child_diff = __xml_next(child_diff)) {
            CRM_CHECK(root_nodes_seen == 0, rc = FALSE);
            if (root_nodes_seen == 0) {
                __add_xml_object(NULL, xml, child_diff);
            }
            root_nodes_seen++;
        }
    }

    CRM_LOG_ASSERT(digest);
    if (root_nodes_seen > 1) {
        crm_err("(+) Diffs cannot contain more than one change set... saw %d", root_nodes_seen);
        rc = -ENOTUNIQ;
    }

    purge_diff_markers(xml);       /* Purge prior to checking the digest */

    free_xml(old);
    free(version);
    return rc;
}

static xmlNode *
__first_xml_child_match(xmlNode *parent, const char *name, const char *id)
{
    xmlNode *cIter = NULL;

    for (cIter = __xml_first_child(parent); cIter != NULL; cIter = __xml_next(cIter)) {
        if(strcmp((const char *)cIter->name, name) != 0) {
            continue;
        } else if(id) {
            const char *cid = ID(cIter);
            if(cid == NULL || strcmp(cid, id) != 0) {
                continue;
            }
        }
        return cIter;
    }
    return NULL;
}

static xmlNode *
__xml_find_path(xmlNode *top, const char *key)
{
    xmlNode *target = (xmlNode*)top->doc;
    char *id = malloc(XML_BUFFER_SIZE);
    char *tag = malloc(XML_BUFFER_SIZE);
    char *section = malloc(XML_BUFFER_SIZE);
    char *current = strdup(key);
    char *remainder = malloc(XML_BUFFER_SIZE);
    int rc = 0;

    while(current) {
        rc = sscanf (current, "/%[^/]%s", section, remainder);
        if(rc <= 0) {
            crm_trace("Done");
            break;

        } else if(rc > 2) {
            crm_trace("Aborting on %s", current);
            target = NULL;
            break;

        } else {
            int f = sscanf (section, "%[^[][@id='%[^']", tag, id);

            switch(f) {
                case 1:
                    target = __first_xml_child_match(target, tag, NULL);
                    break;
                case 2:
                    target = __first_xml_child_match(target, tag, id);
                    break;
                default:
                    crm_trace("Aborting on %s", section);
                    target = NULL;
                    break;
            }

            if(rc == 1 || target == NULL) {
                crm_trace("Done");
                break;

            } else {
                char *tmp = current;
                current = remainder;
                remainder = tmp;
            }
        }
    }

    if(target) {
        char *path = (char *)xmlGetNodePath(target);

        crm_trace("Found %s for %s", path, key);
        free(path);
    } else {
        crm_notice("No match for %s", key);
    }

    free(remainder);
    free(current);
    free(tag);
    return target;
}

static int
xml_apply_patchset_v2(xmlNode *xml, xmlNode *patchset, bool check_version) 
{
    int rc = pcmk_ok;
    xmlNode *change = NULL;
    for (change = __xml_first_child(patchset); change != NULL; change = __xml_next(change)) {
        xmlNode *match = NULL;
        const char *op = crm_element_value(change, XML_DIFF_OP);
        const char *xpath = crm_element_value(change, XML_DIFF_PATH);

        crm_trace("Processing %s %s", change->name, op);
        if(op == NULL) {
            continue;
        }

#if 0
        match = get_xpath_object(xpath, xml, LOG_TRACE);
#else
        match = __xml_find_path(xml, xpath);
#endif
        crm_trace("Performing %s on %s with %p", op, xpath, match);

        if(match == NULL && strcmp(op, "delete") == 0) {
            crm_debug("No %s match for %s in %p", op, xpath, xml->doc);
            continue;

        } else if(match == NULL) {
            crm_err("No %s match for %s in %p", op, xpath, xml->doc);
            rc = -pcmk_err_diff_failed;
            continue;

        } else if(strcmp(op, "create") == 0) {
            int position = 0;
            xmlNode *child = NULL;
            xmlNode *match_child = NULL;

            match_child = match->children;
            crm_element_value_int(change, XML_DIFF_POSITION, &position);

            while(match_child && position != __xml_offset(match_child)) {
                match_child = match_child->next;
            }

            child = xmlDocCopyNode(change->children, match->doc, 1);
            if(match_child) {
                crm_info("Adding %s at position %d", child->name, position);
                xmlAddPrevSibling(match_child, child);

            } else if(match->last) { /* Add to the end */
                crm_trace("Adding %s at position %d (end)", child->name, position);
                xmlAddNextSibling(match->last, child);

            } else {
                crm_trace("Adding %s at position %d (first)", child->name, position);
                CRM_LOG_ASSERT(position == 0);
                xmlAddChild(match, child);
            }
            crm_node_created(child);

        } else if(strcmp(op, "move") == 0) {
            int position = 0;

            crm_element_value_int(change, XML_DIFF_POSITION, &position);
            if(position != __xml_offset(match)) {
                xmlNode *match_child = NULL;
                int p = position;

                if(p > __xml_offset(match)) {
                    p++; /* Skip ourselves */
                }

                CRM_ASSERT(match->parent != NULL);
                match_child = match->parent->children;

                while(match_child && p != __xml_offset(match_child)) {
                    match_child = match_child->next;
                }

                crm_info("Moving %s to position %d (was %d, prev %p, %s %p)",
                         match->name, position, __xml_offset(match), match->prev,
                         match_child?"next":"last", match_child?match_child:match->parent->last);

                if(match_child) {
                    xmlAddPrevSibling(match_child, match);

                } else {
                    CRM_ASSERT(match->parent->last != NULL);
                    xmlAddNextSibling(match->parent->last, match);
                }

            } else {
                crm_trace("%s is already in position %d", match->name, position);
            }

            if(position != __xml_offset(match)) {
                crm_err("Moved %s.%d to position %d instead of %d (%p)",
                        match->name, ID(match), __xml_offset(match), position, match->prev);
                rc = -pcmk_err_diff_failed;
            }

        } else if(strcmp(op, "delete") == 0) {
            free_xml(match);

        } else if(strcmp(op, "modify") == 0) {
            xmlAttr *pIter = crm_first_attr(match);
            xmlNode *attrs = __xml_first_child(first_named_child(change, XML_DIFF_RESULT));

            if(attrs == NULL) {
                rc = -ENOMSG;
                continue;
            }
            while(pIter != NULL) {
                const char *name = (const char *)pIter->name;

                pIter = pIter->next;
                xml_remove_prop(match, name);
            }

            for (pIter = crm_first_attr(attrs); pIter != NULL; pIter = pIter->next) {
                const char *name = (const char *)pIter->name;
                const char *value = crm_element_value(attrs, name);

                crm_xml_add(match, name, value);
            }

        } else {
            crm_err("Unknown operation: %s", op);
        }
    }
    return rc;
}

int
xml_apply_patchset(xmlNode *xml, xmlNode *patchset, bool check_version) 
{
    int format = 1;
    int rc = pcmk_ok;
    xmlNode *old = NULL;
    const char *digest = crm_element_value(patchset, XML_ATTR_DIGEST);

    if(patchset == NULL) {
        return rc;
    }

    xml_log_patchset(LOG_TRACE, __FUNCTION__, patchset);

    crm_element_value_int(patchset, "format", &format);
    if(check_version) {
        rc = xml_patch_version_check(xml, patchset, format);
    }

    if(digest) {
        /* Make it available for logging if the result doesn't have the expected digest */
        old = copy_xml(xml);
    }

    if(rc == pcmk_ok) {
        switch(format) {
            case 1:
                rc = xml_apply_patchset_v1(xml, patchset, check_version);
                break;
            case 2:
                rc = xml_apply_patchset_v2(xml, patchset, check_version);
                break;
            default:
                crm_err("Unknown patch format: %d", format);
                rc = -EINVAL;
        }
    }

    if(rc == pcmk_ok && digest) {
        static struct qb_log_callsite *digest_cs = NULL;

        char *new_digest = NULL;
        char *version = crm_element_value_copy(xml, XML_ATTR_CRM_VERSION);

        if (digest_cs == NULL) {
            digest_cs =
                qb_log_callsite_get(__func__, __FILE__, "diff-digest", LOG_TRACE, __LINE__,
                                    crm_trace_nonlog);
        }

        new_digest = calculate_xml_versioned_digest(xml, FALSE, TRUE, version);
        if (safe_str_neq(new_digest, digest)) {
            crm_info("Digest mis-match: expected %s, calculated %s", digest, new_digest);
            rc = -pcmk_err_diff_failed;

            if (digest_cs && digest_cs->targets) {
                save_xml_to_file(old,     "PatchDigest:input", NULL);
                save_xml_to_file(xml,     "PatchDigest:result", NULL);
                save_xml_to_file(patchset,"PatchDigest:diff", NULL);

            } else {
                crm_trace("%p %0.6x", digest_cs, digest_cs ? digest_cs->targets : 0);
            }

        } else {
            crm_trace("Digest matched: expected %s, calculated %s", digest, new_digest);
        }
        free(new_digest);
    }
    free_xml(old);
    return rc;
}

xmlNode *
find_xml_node(xmlNode * root, const char *search_path, gboolean must_find)
{
    xmlNode *a_child = NULL;
    const char *name = "NULL";

    if (root != NULL) {
        name = crm_element_name(root);
    }

    if (search_path == NULL) {
        crm_warn("Will never find <NULL>");
        return NULL;
    }

    for (a_child = __xml_first_child(root); a_child != NULL; a_child = __xml_next(a_child)) {
        if (strcmp((const char *)a_child->name, search_path) == 0) {
/* 		crm_trace("returning node (%s).", crm_element_name(a_child)); */
            return a_child;
        }
    }

    if (must_find) {
        crm_warn("Could not find %s in %s.", search_path, name);
    } else if (root != NULL) {
        crm_trace("Could not find %s in %s.", search_path, name);
    } else {
        crm_trace("Could not find %s in <NULL>.", search_path);
    }

    return NULL;
}

xmlNode *
find_entity(xmlNode * parent, const char *node_name, const char *id)
{
    xmlNode *a_child = NULL;

    for (a_child = __xml_first_child(parent); a_child != NULL; a_child = __xml_next(a_child)) {
        /* Uncertain if node_name == NULL check is strictly necessary here */
        if (node_name == NULL || strcmp((const char *)a_child->name, node_name) == 0) {
            if (id == NULL || strcmp(id, ID(a_child)) == 0) {
                return a_child;
            }
        }
    }

    crm_trace("node <%s id=%s> not found in %s.", node_name, id, crm_element_name(parent));
    return NULL;
}

void
copy_in_properties(xmlNode * target, xmlNode * src)
{
    if (src == NULL) {
        crm_warn("No node to copy properties from");

    } else if (target == NULL) {
        crm_err("No node to copy properties into");

    } else {
        xmlAttrPtr pIter = NULL;

        for (pIter = crm_first_attr(src); pIter != NULL; pIter = pIter->next) {
            const char *p_name = (const char *)pIter->name;
            const char *p_value = crm_attr_value(pIter);

            expand_plus_plus(target, p_name, p_value);
        }
    }

    return;
}

void
fix_plus_plus_recursive(xmlNode * target)
{
    /* TODO: Remove recursion and use xpath searches for value++ */
    xmlNode *child = NULL;
    xmlAttrPtr pIter = NULL;

    for (pIter = crm_first_attr(target); pIter != NULL; pIter = pIter->next) {
        const char *p_name = (const char *)pIter->name;
        const char *p_value = crm_attr_value(pIter);

        expand_plus_plus(target, p_name, p_value);
    }
    for (child = __xml_first_child(target); child != NULL; child = __xml_next(child)) {
        fix_plus_plus_recursive(child);
    }
}

void
expand_plus_plus(xmlNode * target, const char *name, const char *value)
{
    int offset = 1;
    int name_len = 0;
    int int_value = 0;
    int value_len = 0;

    const char *old_value = NULL;

    if (value == NULL || name == NULL) {
        return;
    }

    old_value = crm_element_value(target, name);

    if (old_value == NULL) {
        /* if no previous value, set unexpanded */
        goto set_unexpanded;

    } else if (strstr(value, name) != value) {
        goto set_unexpanded;
    }

    name_len = strlen(name);
    value_len = strlen(value);
    if (value_len < (name_len + 2)
        || value[name_len] != '+' || (value[name_len + 1] != '+' && value[name_len + 1] != '=')) {
        goto set_unexpanded;
    }

    /* if we are expanding ourselves,
     * then no previous value was set and leave int_value as 0
     */
    if (old_value != value) {
        int_value = char2score(old_value);
    }

    if (value[name_len + 1] != '+') {
        const char *offset_s = value + (name_len + 2);

        offset = char2score(offset_s);
    }
    int_value += offset;

    if (int_value > INFINITY) {
        int_value = INFINITY;
    }

    crm_xml_add_int(target, name, int_value);
    return;

  set_unexpanded:
    if (old_value == value) {
        /* the old value is already set, nothing to do */
        return;
    }
    crm_xml_add(target, name, value);
    return;
}

xmlDoc *
getDocPtr(xmlNode * node)
{
    xmlDoc *doc = NULL;

    CRM_CHECK(node != NULL, return NULL);

    doc = node->doc;
    if (doc == NULL) {
        doc = xmlNewDoc((const xmlChar *)"1.0");
        xmlDocSetRootElement(doc, node);
        xmlSetTreeDoc(node, doc);
    }
    return doc;
}

xmlNode *
add_node_copy(xmlNode * parent, xmlNode * src_node)
{
    xmlNode *child = NULL;
    xmlDoc *doc = getDocPtr(parent);

    CRM_CHECK(src_node != NULL, return NULL);

    child = xmlDocCopyNode(src_node, doc, 1);
    xmlAddChild(parent, child);
    crm_node_created(child);
    return child;
}

int
add_node_nocopy(xmlNode * parent, const char *name, xmlNode * child)
{
    add_node_copy(parent, child);
    free_xml(child);
    return 1;
}

const char *
crm_xml_add(xmlNode * node, const char *name, const char *value)
{
    bool dirty = FALSE;
    xmlAttr *attr = NULL;

    CRM_CHECK(node != NULL, return NULL);
    CRM_CHECK(name != NULL, return NULL);

    if (value == NULL) {
        return NULL;
    }
#if XML_PARANOIA_CHECKS
    {
        const char *old_value = NULL;

        old_value = crm_element_value(node, name);

        /* Could be re-setting the same value */
        CRM_CHECK(old_value != value, crm_err("Cannot reset %s with crm_xml_add(%s)", name, value);
                  return value);
    }
#endif

    if(TRACKING_CHANGES(node)) {
        const char *old = crm_element_value(node, name);

        if(old == NULL || value == NULL || strcmp(old, value) != 0) {
            dirty = TRUE;
        }
    }

    attr = xmlSetProp(node, (const xmlChar *)name, (const xmlChar *)value);
    if(dirty) {
        crm_attr_dirty(attr);
    }

    CRM_CHECK(attr && attr->children && attr->children->content, return NULL);
    return (char *)attr->children->content;
}

const char *
crm_xml_replace(xmlNode * node, const char *name, const char *value)
{
    bool dirty = FALSE;
    xmlAttr *attr = NULL;
    const char *old_value = NULL;

    CRM_CHECK(node != NULL, return NULL);
    CRM_CHECK(name != NULL && name[0] != 0, return NULL);

    old_value = crm_element_value(node, name);

    /* Could be re-setting the same value */
    CRM_CHECK(old_value != value, return value);

    if (old_value != NULL && value == NULL) {
        xml_remove_prop(node, name);
        return NULL;

    } else if (value == NULL) {
        return NULL;
    }

    if(TRACKING_CHANGES(node)) {
        if(old_value == NULL || value == NULL || strcmp(old_value, value) != 0) {
            dirty = TRUE;
        }
    }

    attr = xmlSetProp(node, (const xmlChar *)name, (const xmlChar *)value);
    if(dirty) {
        crm_attr_dirty(attr);
    }
    CRM_CHECK(attr && attr->children && attr->children->content, return NULL);
    return (char *)attr->children->content;
}

const char *
crm_xml_add_int(xmlNode * node, const char *name, int value)
{
    char *number = crm_itoa(value);
    const char *added = crm_xml_add(node, name, number);

    free(number);
    return added;
}

xmlNode *
create_xml_node(xmlNode * parent, const char *name)
{
    xmlDoc *doc = NULL;
    xmlNode *node = NULL;

    if (name == NULL || name[0] == 0) {
        return NULL;
    }

    if (parent == NULL) {
        doc = xmlNewDoc((const xmlChar *)"1.0");
        node = xmlNewDocRawNode(doc, NULL, (const xmlChar *)name, NULL);
        xmlDocSetRootElement(doc, node);

    } else {
        doc = getDocPtr(parent);
        node = xmlNewDocRawNode(doc, NULL, (const xmlChar *)name, NULL);
        xmlAddChild(parent, node);
    }
    crm_node_created(node);
    return node;
}

static inline int
__get_prefix(const char *prefix, xmlNode *xml, char *buffer, int offset)
{
    const char *id = ID(xml);

    if(offset == 0 && prefix == NULL && xml->parent) {
        offset = __get_prefix(NULL, xml->parent, buffer, offset);
    }

    if(id) {
        offset += snprintf(buffer + offset, XML_BUFFER_SIZE - offset, "/%s[@id='%s']", (const char *)xml->name, id);
    } else if(xml->name) {
        offset += snprintf(buffer + offset, XML_BUFFER_SIZE - offset, "/%s", (const char *)xml->name);
    }

    return offset;
}

void
free_xml(xmlNode * child)
{
    if (child != NULL) {
        xmlNode *top = NULL;
        xmlDoc *doc = child->doc;
        xml_private_t *p = child->_private;

        if (doc != NULL) {
            top = xmlDocGetRootElement(doc);
        }

        if (doc != NULL && top == child) {
            /* Free everything */
            xmlFreeDoc(doc);

        } else {
            if(TRACKING_CHANGES(child) && is_not_set(p->flags, xpf_created)) {
                int offset = 0;
                char buffer[XML_BUFFER_SIZE];

                if(__get_prefix(NULL, child, buffer, offset) > 0) {
                    crm_trace("Deleting %s %p from %p", buffer, child, doc);
                    p = doc->_private;
                    p->deleted_paths = g_list_append(p->deleted_paths, strdup(buffer));
                    set_doc_flag(child, xpf_dirty);
                }
            }

            /* Free this particular subtree
             * Make sure to unlink it from the parent first
             */
            xmlUnlinkNode(child);
            xmlFreeNode(child);
        }
    }
}

xmlNode *
copy_xml(xmlNode * src)
{
    xmlDoc *doc = xmlNewDoc((const xmlChar *)"1.0");
    xmlNode *copy = xmlDocCopyNode(src, doc, 1);

    xmlDocSetRootElement(doc, copy);
    xmlSetTreeDoc(copy, doc);
    return copy;
}

static void
crm_xml_err(void *ctx, const char *msg, ...)
G_GNUC_PRINTF(2, 3);

static void
crm_xml_err(void *ctx, const char *msg, ...)
{
    int len = 0;
    va_list args;
    char *buf = NULL;
    static int buffer_len = 0;
    static char *buffer = NULL;
    static struct qb_log_callsite *xml_error_cs = NULL;

    va_start(args, msg);
    len = vasprintf(&buf, msg, args);

    if(xml_error_cs == NULL) {
        xml_error_cs = qb_log_callsite_get(
            __func__, __FILE__, "xml library error", LOG_TRACE, __LINE__, crm_trace_nonlog);
    }

    if (strchr(buf, '\n')) {
        buf[len - 1] = 0;
        if (buffer) {
            crm_err("XML Error: %s%s", buffer, buf);
            free(buffer);
        } else {
            crm_err("XML Error: %s", buf);
        }
        if (xml_error_cs && xml_error_cs->targets) {
            crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__, "xml library error", TRUE, TRUE);
        }
        buffer = NULL;
        buffer_len = 0;

    } else if (buffer == NULL) {
        buffer_len = len;
        buffer = buf;
        buf = NULL;

    } else {
        buffer = realloc(buffer, 1 + buffer_len + len);
        memcpy(buffer + buffer_len, buf, len);
        buffer_len += len;
        buffer[buffer_len] = 0;
    }

    va_end(args);
    free(buf);
}

xmlNode *
string2xml(const char *input)
{
    xmlNode *xml = NULL;
    xmlDocPtr output = NULL;
    xmlParserCtxtPtr ctxt = NULL;
    xmlErrorPtr last_error = NULL;

    if (input == NULL) {
        crm_err("Can't parse NULL input");
        return NULL;
    }

    /* create a parser context */
    ctxt = xmlNewParserCtxt();
    CRM_CHECK(ctxt != NULL, return NULL);

    /* xmlCtxtUseOptions(ctxt, XML_PARSE_NOBLANKS|XML_PARSE_RECOVER); */

    xmlCtxtResetLastError(ctxt);
    xmlSetGenericErrorFunc(ctxt, crm_xml_err);
    /* initGenericErrorDefaultFunc(crm_xml_err); */
    output =
        xmlCtxtReadDoc(ctxt, (const xmlChar *)input, NULL, NULL,
                       XML_PARSE_NOBLANKS | XML_PARSE_RECOVER);
    if (output) {
        xml = xmlDocGetRootElement(output);
    }
    last_error = xmlCtxtGetLastError(ctxt);
    if (last_error && last_error->code != XML_ERR_OK) {
        /* crm_abort(__FILE__,__PRETTY_FUNCTION__,__LINE__, "last_error->code != XML_ERR_OK", TRUE, TRUE); */
        /*
         * http://xmlsoft.org/html/libxml-xmlerror.html#xmlErrorLevel
         * http://xmlsoft.org/html/libxml-xmlerror.html#xmlParserErrors
         */
        crm_warn("Parsing failed (domain=%d, level=%d, code=%d): %s",
                 last_error->domain, last_error->level, last_error->code, last_error->message);

        if (last_error->code == XML_ERR_DOCUMENT_EMPTY) {
            crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__, "Cannot parse an empty string", TRUE,
                      TRUE);

        } else if (last_error->code != XML_ERR_DOCUMENT_END) {
            crm_err("Couldn't%s parse %d chars: %s", xml ? " fully" : "", (int)strlen(input),
                    input);
            if (xml != NULL) {
                crm_log_xml_err(xml, "Partial");
            }

        } else {
            int len = strlen(input);
            int lpc = 0;

            while(lpc < len) {
                crm_warn("Parse error[+%.3d]: %.80s", lpc, input+lpc);
                lpc += 80;
            }

            crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__, "String parsing error", TRUE, TRUE);
        }
    }

    xmlFreeParserCtxt(ctxt);
    return xml;
}

xmlNode *
stdin2xml(void)
{
    size_t data_length = 0;
    size_t read_chars = 0;

    char *xml_buffer = NULL;
    xmlNode *xml_obj = NULL;

    do {
        size_t next = XML_BUFFER_SIZE + data_length + 1;

        if(next <= 0) {
            crm_err("Buffer size exceeded at: %l + %d", data_length, XML_BUFFER_SIZE);
            break;
        }

        xml_buffer = realloc(xml_buffer, next);
        read_chars = fread(xml_buffer + data_length, 1, XML_BUFFER_SIZE, stdin);
        data_length += read_chars;
    } while (read_chars > 0);

    if (data_length == 0) {
        crm_warn("No XML supplied on stdin");
        free(xml_buffer);
        return NULL;
    }

    xml_buffer[data_length] = '\0';

    xml_obj = string2xml(xml_buffer);
    free(xml_buffer);

    crm_log_xml_trace(xml_obj, "Created fragment");
    return xml_obj;
}

static char *
decompress_file(const char *filename)
{
    char *buffer = NULL;

#if HAVE_BZLIB_H
    int rc = 0;
    size_t length = 0, read_len = 0;

    BZFILE *bz_file = NULL;
    FILE *input = fopen(filename, "r");

    if (input == NULL) {
        crm_perror(LOG_ERR, "Could not open %s for reading", filename);
        return NULL;
    }

    bz_file = BZ2_bzReadOpen(&rc, input, 0, 0, NULL, 0);

    if (rc != BZ_OK) {
        BZ2_bzReadClose(&rc, bz_file);
        return NULL;
    }

    rc = BZ_OK;
    while (rc == BZ_OK) {
        buffer = realloc(buffer, XML_BUFFER_SIZE + length + 1);
        read_len = BZ2_bzRead(&rc, bz_file, buffer + length, XML_BUFFER_SIZE);

        crm_trace("Read %ld bytes from file: %d", (long)read_len, rc);

        if (rc == BZ_OK || rc == BZ_STREAM_END) {
            length += read_len;
        }
    }

    buffer[length] = '\0';
    read_len = length;

    if (rc != BZ_STREAM_END) {
        crm_err("Couldnt read compressed xml from file");
        free(buffer);
        buffer = NULL;
    }

    BZ2_bzReadClose(&rc, bz_file);
    fclose(input);

#else
    crm_err("Cannot read compressed files:" " bzlib was not available at compile time");
#endif
    return buffer;
}

void
strip_text_nodes(xmlNode * xml)
{
    xmlNode *iter = xml->children;

    while (iter) {
        xmlNode *next = iter->next;

        switch (iter->type) {
            case XML_TEXT_NODE:
                /* Remove it */
                xmlUnlinkNode(iter);
                xmlFreeNode(iter);
                break;

            case XML_ELEMENT_NODE:
                /* Search it */
                strip_text_nodes(iter);
                break;

            default:
                /* Leave it */
                break;
        }

        iter = next;
    }
}

xmlNode *
filename2xml(const char *filename)
{
    xmlNode *xml = NULL;
    xmlDocPtr output = NULL;
    const char *match = NULL;
    xmlParserCtxtPtr ctxt = NULL;
    xmlErrorPtr last_error = NULL;
    static int xml_options = XML_PARSE_NOBLANKS | XML_PARSE_RECOVER;

    /* create a parser context */
    ctxt = xmlNewParserCtxt();
    CRM_CHECK(ctxt != NULL, return NULL);

    /* xmlCtxtUseOptions(ctxt, XML_PARSE_NOBLANKS|XML_PARSE_RECOVER); */

    xmlCtxtResetLastError(ctxt);
    xmlSetGenericErrorFunc(ctxt, crm_xml_err);
    /* initGenericErrorDefaultFunc(crm_xml_err); */

    if (filename) {
        match = strstr(filename, ".bz2");
    }

    if (filename == NULL) {
        /* STDIN_FILENO == fileno(stdin) */
        output = xmlCtxtReadFd(ctxt, STDIN_FILENO, "unknown.xml", NULL, xml_options);

    } else if (match == NULL || match[4] != 0) {
        output = xmlCtxtReadFile(ctxt, filename, NULL, xml_options);

    } else {
        char *input = decompress_file(filename);

        output = xmlCtxtReadDoc(ctxt, (const xmlChar *)input, NULL, NULL, xml_options);
        free(input);
    }

    if (output && (xml = xmlDocGetRootElement(output))) {
        strip_text_nodes(xml);
    }

    last_error = xmlCtxtGetLastError(ctxt);
    if (last_error && last_error->code != XML_ERR_OK) {
        /* crm_abort(__FILE__,__PRETTY_FUNCTION__,__LINE__, "last_error->code != XML_ERR_OK", TRUE, TRUE); */
        /*
         * http://xmlsoft.org/html/libxml-xmlerror.html#xmlErrorLevel
         * http://xmlsoft.org/html/libxml-xmlerror.html#xmlParserErrors
         */
        crm_err("Parsing failed (domain=%d, level=%d, code=%d): %s",
                last_error->domain, last_error->level, last_error->code, last_error->message);

        if (last_error && last_error->code != XML_ERR_OK) {
            crm_err("Couldn't%s parse %s", xml ? " fully" : "", filename);
            if (xml != NULL) {
                crm_log_xml_err(xml, "Partial");
            }
        }
    }

    xmlFreeParserCtxt(ctxt);
    return xml;
}

static int
write_xml_stream(xmlNode * xml_node, const char *filename, FILE * stream, gboolean compress)
{
    int res = 0;
    char *buffer = NULL;
    unsigned int out = 0;
    static mode_t cib_mode = S_IRUSR | S_IWUSR;

    CRM_CHECK(stream != NULL, return -1);

    crm_trace("Writing XML out to %s", filename);
    if (xml_node == NULL) {
        crm_err("Cannot write NULL to %s", filename);
        fclose(stream);
        return -1;
    }


    crm_log_xml_trace(xml_node, "Writing out");

    if(strstr(filename, "cib") != NULL) {
        /* Only CIB's need this field written */
        time_t now = time(NULL);
        char *now_str = ctime(&now);

        now_str[24] = EOS;          /* replace the newline */
        crm_xml_add(xml_node, XML_CIB_ATTR_WRITTEN, now_str);

        /* establish the correct permissions */
        fchmod(fileno(stream), cib_mode);
    }

    buffer = dump_xml_formatted(xml_node);
    CRM_CHECK(buffer != NULL && strlen(buffer) > 0, crm_log_xml_warn(xml_node, "dump:failed");
              goto bail);

    if (compress) {
#if HAVE_BZLIB_H
        int rc = BZ_OK;
        unsigned int in = 0;
        BZFILE *bz_file = NULL;

        bz_file = BZ2_bzWriteOpen(&rc, stream, 5, 0, 30);
        if (rc != BZ_OK) {
            crm_err("bzWriteOpen failed: %d", rc);
        } else {
            BZ2_bzWrite(&rc, bz_file, buffer, strlen(buffer));
            if (rc != BZ_OK) {
                crm_err("bzWrite() failed: %d", rc);
            }
        }

        if (rc == BZ_OK) {
            BZ2_bzWriteClose(&rc, bz_file, 0, &in, &out);
            if (rc != BZ_OK) {
                crm_err("bzWriteClose() failed: %d", rc);
                out = -1;
            } else {
                crm_trace("%s: In: %d, out: %d", filename, in, out);
            }
        }
#else
        crm_err("Cannot write compressed files:" " bzlib was not available at compile time");
#endif
    }

    if (out <= 0) {
        res = fprintf(stream, "%s", buffer);
        if (res < 0) {
            crm_perror(LOG_ERR, "Cannot write output to %s", filename);
            goto bail;
        }
    }

  bail:

    if (fflush(stream) != 0) {
        crm_perror(LOG_ERR, "fflush for %s failed:", filename);
        res = -1;
    }

    if (fsync(fileno(stream)) < 0) {
        crm_perror(LOG_ERR, "fsync for %s failed:", filename);
        res = -1;
    }

    fclose(stream);

    crm_trace("Saved %d bytes to the Cib as XML", res);
    free(buffer);

    return res;
}

int
write_xml_fd(xmlNode * xml_node, const char *filename, int fd, gboolean compress)
{
    FILE *stream = NULL;

    CRM_CHECK(fd > 0, return -1);
    stream = fdopen(fd, "w");
    return write_xml_stream(xml_node, filename, stream, compress);
}

int
write_xml_file(xmlNode * xml_node, const char *filename, gboolean compress)
{
    FILE *stream = NULL;

    stream = fopen(filename, "w");

    return write_xml_stream(xml_node, filename, stream, compress);
}

xmlNode *
get_message_xml(xmlNode * msg, const char *field)
{
    xmlNode *tmp = first_named_child(msg, field);

    return __xml_first_child(tmp);
}

gboolean
add_message_xml(xmlNode * msg, const char *field, xmlNode * xml)
{
    xmlNode *holder = create_xml_node(msg, field);

    add_node_copy(holder, xml);
    return TRUE;
}

static char *
crm_xml_escape_shuffle(char *text, int start, int *length, const char *replace)
{
    int lpc;
    int offset = strlen(replace) - 1;   /* We have space for 1 char already */

    *length += offset;
    text = realloc(text, *length);

    for (lpc = (*length) - 1; lpc > (start + offset); lpc--) {
        text[lpc] = text[lpc - offset];
    }

    memcpy(text + start, replace, offset + 1);
    return text;
}

static char *
crm_xml_escape(const char *text)
{
    int index;
    int changes = 0;
    int length = 1 + strlen(text);
    char *copy = strdup(text);

    /*
     * When xmlCtxtReadDoc() parses &lt; and friends in a
     * value, it converts them to their human readable
     * form.
     *
     * If one uses xmlNodeDump() to convert it back to a
     * string, all is well, because special characters are
     * converted back to their escape sequences.
     *
     * However xmlNodeDump() is randomly dog slow, even with the same
     * input. So we need to replicate the escapeing in our custom
     * version so that the result can be re-parsed by xmlCtxtReadDoc()
     * when necessary.
     */

    for (index = 0; index < length; index++) {
        switch (copy[index]) {
            case 0:
                break;
            case '<':
                copy = crm_xml_escape_shuffle(copy, index, &length, "&lt;");
                changes++;
                break;
            case '>':
                copy = crm_xml_escape_shuffle(copy, index, &length, "&gt;");
                changes++;
                break;
            case '"':
                copy = crm_xml_escape_shuffle(copy, index, &length, "&quot;");
                changes++;
                break;
            case '\'':
                copy = crm_xml_escape_shuffle(copy, index, &length, "&apos;");
                changes++;
                break;
            case '&':
                copy = crm_xml_escape_shuffle(copy, index, &length, "&amp;");
                changes++;
                break;
            case '\t':
                /* Might as well just expand to a few spaces... */
                copy = crm_xml_escape_shuffle(copy, index, &length, "    ");
                changes++;
                break;
            case '\n':
                /* crm_trace("Convert: \\%.3o", copy[index]); */
                copy = crm_xml_escape_shuffle(copy, index, &length, "\\n");
                changes++;
                break;
            case '\r':
                copy = crm_xml_escape_shuffle(copy, index, &length, "\\r");
                changes++;
                break;
                /* For debugging...
            case '\\':
                crm_trace("Passthrough: \\%c", copy[index+1]);
                break;
                */
            default:
                /* Check for and replace non-printing characters with their octal equivalent */
                if(copy[index] < ' ' || copy[index] > '~') {
                    char *replace = g_strdup_printf("\\%.3o", copy[index]);

                    /* crm_trace("Convert to octal: \\%.3o", copy[index]); */
                    copy = crm_xml_escape_shuffle(copy, index, &length, replace);
                    free(replace);
                    changes++;
                }
        }
    }

    if (changes) {
        crm_trace("Dumped '%s'", copy);
    }
    return copy;
}

static inline void
dump_xml_attr(xmlAttrPtr attr, int options, char **buffer, int *offset, int *max)
{
    char *p_value = NULL;
    const char *p_name = NULL;

    if (attr == NULL || attr->children == NULL) {
        return;
    }

    p_name = (const char *)attr->name;
    p_value = crm_xml_escape((const char *)attr->children->content);
    buffer_print(*buffer, *max, *offset, " %s=\"%s\"", p_name, p_value);
    free(p_value);
}

void
log_data_element(int log_level, const char *file, const char *function, int line,
                 const char *prefix, xmlNode * data, int depth, int options)
{
    xmlNode *a_child = NULL;

    int max = 0;
    int offset = 0;
    char *buffer = NULL;
    char *prefix_m = NULL;

    xmlAttrPtr pIter = NULL;
    const char *name = NULL;
    const char *hidden = NULL;

    if (prefix == NULL) {
        prefix = "";
    }

    /* Since we use the same file and line, to avoid confusing libqb, we need to use the same format strings */
    if (data == NULL) {
        do_crm_log_alias(log_level, file, function, line, "%s: %s", prefix,
                         "No data to dump as XML");
        return;
    }

    name = crm_element_name(data);

    if(is_set(options, xml_log_option_dirty_add)) {
        xml_private_t *p = data->_private;

        if(is_set(p->flags, xpf_dirty) && is_set(p->flags, xpf_created)) {
            /* Continue and log full subtree */
            prefix_m = strdup(prefix);
            prefix_m[1] = '+';
            prefix = prefix_m;
            goto dolog;

        } else if(is_set(p->flags, xpf_dirty)) {
            char *spaces = calloc(80, 1);
            int s_count = 0, s_max = 80;

            insert_prefix(options, &spaces, &s_count, &s_max, depth);
            prefix_m = strdup(prefix);
            prefix_m[1] = '+';

            for (pIter = crm_first_attr(data); pIter != NULL; pIter = pIter->next) {

                p = pIter->_private;
                if(is_not_set(p->flags, xpf_deleted) && is_set(p->flags, xpf_dirty)) {
                    const char *aname = (const char*)pIter->name;
                    const char *value = crm_element_value(data, aname);

                    if(is_set(p->flags, xpf_created)) {
                        do_crm_log_alias(log_level, file, function, line,
                                         "%s %s@%s=%s", prefix_m, spaces, aname, value);
                    } else {
                        do_crm_log_alias(log_level, file, function, line,
                                         "%s %s@%s=%s", prefix, spaces, aname, value);
                    }
                }
            }
            free(spaces);
            free(prefix_m);
            prefix_m = NULL;
            goto dolog;

        } else {
            for (a_child = __xml_first_child(data); a_child != NULL; a_child = __xml_next(a_child)) {
                log_data_element(log_level, file, function, line, prefix, a_child, depth + 1, options);
            }
            return;
        }

    } else if(is_set(options, xml_log_option_dirty_del)) {
        xml_private_t *p = data->_private;

        if(is_set(p->flags, xpf_dirty)) {
            char *spaces = calloc(80, 1);
            int s_count = 0, s_max = 80;

            insert_prefix(options, &spaces, &s_count, &s_max, depth);
            prefix_m = strdup(prefix);
            prefix_m[1] = '-';

            for (pIter = crm_first_attr(data); pIter != NULL; pIter = pIter->next) {

                p = pIter->_private;
                if(is_set(p->flags, xpf_deleted)) {
                    char *path = (char *)xmlGetNodePath(data);
                    const char *aname = (const char*)pIter->name;
                    const char *value = crm_element_value(data, aname);

                    do_crm_log_alias(log_level, file, function, line,
                                     "%s %s@%s=%s", prefix_m, spaces, aname, value);
                    free(path);
                }
            }
            for (a_child = __xml_first_child(data); a_child != NULL; a_child = __xml_next(a_child)) {
                log_data_element(log_level, file, function, line, prefix, a_child, depth + 1, options);
            }
            free(prefix_m);
            free(spaces);
            return;

        } else {
            for (a_child = __xml_first_child(data); a_child != NULL; a_child = __xml_next(a_child)) {
                log_data_element(log_level, file, function, line, prefix, a_child, depth + 1, options);
            }
            return;
        }
    }

    if (is_set(options, xml_log_option_formatted)) {
        if (is_set(options, xml_log_option_diff_plus)
            && (data->children == NULL || crm_element_value(data, XML_DIFF_MARKER))) {
            options |= xml_log_option_diff_all;
            prefix_m = strdup(prefix);
            prefix_m[1] = '+';
            prefix = prefix_m;

        } else if (is_set(options, xml_log_option_diff_minus)
                   && (data->children == NULL || crm_element_value(data, XML_DIFF_MARKER))) {
            options |= xml_log_option_diff_all;
            prefix_m = strdup(prefix);
            prefix_m[1] = '-';
            prefix = prefix_m;
        }
    }

    if (is_set(options, xml_log_option_diff_short)
               && is_not_set(options, xml_log_option_diff_all)) {
        /* Still searching for the actual change */
        for (a_child = __xml_first_child(data); a_child != NULL; a_child = __xml_next(a_child)) {
            log_data_element(log_level, file, function, line, prefix, a_child, depth + 1, options);
        }
        return;
    }

  dolog:
    insert_prefix(options, &buffer, &offset, &max, depth);
    if(data->type == XML_COMMENT_NODE) {
        buffer_print(buffer, max, offset, "<!--");
        buffer_print(buffer, max, offset, "%s", data->content);
        buffer_print(buffer, max, offset, "-->");

    } else {
        buffer_print(buffer, max, offset, "<%s", name);
    }

    hidden = crm_element_value(data, "hidden");
    for (pIter = crm_first_attr(data); pIter != NULL; pIter = pIter->next) {
        const char *p_name = (const char *)pIter->name;
        const char *p_value = crm_attr_value(pIter);
        char *p_copy = NULL;

        if ((is_set(options, xml_log_option_diff_plus)
             || is_set(options, xml_log_option_diff_minus))
            && strcmp(XML_DIFF_MARKER, p_name) == 0) {
            continue;

        } else if (hidden != NULL && p_name[0] != 0 && strstr(hidden, p_name) != NULL) {
            p_copy = strdup("*****");

        } else {
            p_copy = crm_xml_escape(p_value);
        }

        buffer_print(buffer, max, offset, " %s=\"%s\"", p_name, p_copy);
        free(p_copy);
    }

    if (xml_has_children(data)) {
        buffer_print(buffer, max, offset, ">");
    } else {
        buffer_print(buffer, max, offset, "/>");
    }

    do_crm_log_alias(log_level, file, function, line, "%s %s", prefix, buffer);

    if (data->children && data->type != XML_COMMENT_NODE) {
        offset = 0;
        max = 0;
        free(buffer);
        buffer = NULL;

        for (a_child = __xml_first_child(data); a_child != NULL; a_child = __xml_next(a_child)) {
            log_data_element(log_level, file, function, line, prefix, a_child, depth + 1, options);
        }

        insert_prefix(options, &buffer, &offset, &max, depth);
        buffer_print(buffer, max, offset, "</%s>", name);

        do_crm_log_alias(log_level, file, function, line, "%s %s", prefix, buffer);
    }

    free(prefix_m);
    free(buffer);
}

static void
dump_filtered_xml(xmlNode * data, int options, char **buffer, int *offset, int *max)
{
    int lpc;
    xmlAttrPtr xIter = NULL;
    static int filter_len = DIMOF(filter);

    for (lpc = 0; options && lpc < filter_len; lpc++) {
        filter[lpc].found = FALSE;
    }

    for (xIter = crm_first_attr(data); xIter != NULL; xIter = xIter->next) {
        bool skip = FALSE;
        const char *p_name = (const char *)xIter->name;

        for (lpc = 0; skip == FALSE && lpc < filter_len; lpc++) {
            if (filter[lpc].found == FALSE && strcmp(p_name, filter[lpc].string) == 0) {
                filter[lpc].found = TRUE;
                skip = TRUE;
                break;
            }
        }

        if (skip == FALSE) {
            dump_xml_attr(xIter, options, buffer, offset, max);
        }
    }
}

static void
dump_xml(xmlNode * data, int options, char **buffer, int *offset, int *max, int depth);

static void
dump_xml_element(xmlNode * data, int options, char **buffer, int *offset, int *max, int depth)
{
    const char *name = NULL;

    CRM_ASSERT(max != NULL);
    CRM_ASSERT(offset != NULL);
    CRM_ASSERT(buffer != NULL);

    if (data == NULL) {
        crm_trace("Nothing to dump");
        return;
    }

    if (*buffer == NULL) {
        *offset = 0;
        *max = 0;
    }

    name = crm_element_name(data);
    CRM_ASSERT(name != NULL);

    insert_prefix(options, buffer, offset, max, depth);
    buffer_print(*buffer, *max, *offset, "<%s", name);

    if (options & xml_log_option_filtered) {
        dump_filtered_xml(data, options, buffer, offset, max);

    } else {
        xmlAttrPtr xIter = NULL;

        for (xIter = crm_first_attr(data); xIter != NULL; xIter = xIter->next) {
            dump_xml_attr(xIter, options, buffer, offset, max);
        }
    }

    if (data->children == NULL) {
        buffer_print(*buffer, *max, *offset, "/>");

    } else {
        buffer_print(*buffer, *max, *offset, ">");
    }

    if (options & xml_log_option_formatted) {
        buffer_print(*buffer, *max, *offset, "\n");
    }

    if (data->children) {
        xmlNode *xChild = NULL;

        for (xChild = __xml_first_child(data); xChild != NULL; xChild = __xml_next(xChild)) {
            dump_xml(xChild, options, buffer, offset, max, depth + 1);
        }

        insert_prefix(options, buffer, offset, max, depth);
        buffer_print(*buffer, *max, *offset, "</%s>", name);

        if (options & xml_log_option_formatted) {
            buffer_print(*buffer, *max, *offset, "\n");
        }
    }
}

static void
dump_xml_comment(xmlNode * data, int options, char **buffer, int *offset, int *max, int depth)
{
    CRM_ASSERT(max != NULL);
    CRM_ASSERT(offset != NULL);
    CRM_ASSERT(buffer != NULL);

    if (data == NULL) {
        crm_trace("Nothing to dump");
        return;
    }

    if (*buffer == NULL) {
        *offset = 0;
        *max = 0;
    }

    insert_prefix(options, buffer, offset, max, depth);

    buffer_print(*buffer, *max, *offset, "<!--");
    buffer_print(*buffer, *max, *offset, "%s", data->content);
    buffer_print(*buffer, *max, *offset, "-->");

    if (options & xml_log_option_formatted) {
        buffer_print(*buffer, *max, *offset, "\n");
    }
}

static void
dump_xml(xmlNode * data, int options, char **buffer, int *offset, int *max, int depth)
{
#if 0
    if (is_not_set(options, xml_log_option_filtered)) {
        /* Turning this code on also changes the PE tests for some reason
         * (not just newlines).  Figure out why before considering to
         * enable this permanently.
         *
         * It exists to help debug slowness in xmlNodeDump() and
         * potentially if we ever want to go back to it.
         *
         * In theory its a good idea (reuse) but our custom version does
         * better for the filtered case and avoids the final strdup() for
         * everything
         */

        time_t now, next;
        xmlDoc *doc = NULL;
        xmlBuffer *xml_buffer = NULL;

        *buffer = NULL;
        doc = getDocPtr(data);
        /* doc will only be NULL if data is */
        CRM_CHECK(doc != NULL, return);

        now = time(NULL);
        xml_buffer = xmlBufferCreate();
        CRM_ASSERT(xml_buffer != NULL);

        /* The default allocator XML_BUFFER_ALLOC_EXACT does far too many
         * realloc()s and it can take upwards of 18 seconds (yes, seconds)
         * to dump a 28kb tree which XML_BUFFER_ALLOC_DOUBLEIT can do in
         * less than 1 second.
         *
         * We could also use xmlBufferCreateSize() to start with a
         * sane-ish initial size and avoid the first few doubles.
         */
        xmlBufferSetAllocationScheme(xml_buffer, XML_BUFFER_ALLOC_DOUBLEIT);

        *max = xmlNodeDump(xml_buffer, doc, data, 0, (options & xml_log_option_formatted));
        if (*max > 0) {
            *buffer = strdup((char *)xml_buffer->content);
        }

        next = time(NULL);
        if ((now + 1) < next) {
            crm_log_xml_trace(data, "Long time");
            crm_err("xmlNodeDump() -> %dbytes took %ds", *max, next - now);
        }

        xmlBufferFree(xml_buffer);
        return;
    }
#endif

    switch(data->type) {
        case XML_ELEMENT_NODE:
            /* Handle below */
            dump_xml_element(data, options, buffer, offset, max, depth);
            break;
        case XML_TEXT_NODE:
            /* Ignore */
            return;
        case XML_COMMENT_NODE:
            dump_xml_comment(data, options, buffer, offset, max, depth);
            break;
        default:
            crm_warn("Unhandled type: %d", data->type);
            return;

            /*
            XML_ATTRIBUTE_NODE = 2
            XML_CDATA_SECTION_NODE = 4
            XML_ENTITY_REF_NODE = 5
            XML_ENTITY_NODE = 6
            XML_PI_NODE = 7
            XML_DOCUMENT_NODE = 9
            XML_DOCUMENT_TYPE_NODE = 10
            XML_DOCUMENT_FRAG_NODE = 11
            XML_NOTATION_NODE = 12
            XML_HTML_DOCUMENT_NODE = 13
            XML_DTD_NODE = 14
            XML_ELEMENT_DECL = 15
            XML_ATTRIBUTE_DECL = 16
            XML_ENTITY_DECL = 17
            XML_NAMESPACE_DECL = 18
            XML_XINCLUDE_START = 19
            XML_XINCLUDE_END = 20
            XML_DOCB_DOCUMENT_NODE = 21
            */
    }

}

static void
fix_digest_buffer(char **buffer, int *offset, int *max, char c)
{
    buffer_print(*buffer, *max, *offset, "%c", c);
}

static char *
dump_xml_for_digest(xmlNode * an_xml_node)
{
    char *buffer = NULL;
    int offset = 0, max = 0;

    /* for compatability with the old result which is used for v1 digests */
    fix_digest_buffer(&buffer, &offset, &max, ' ');
    dump_xml(an_xml_node, 0, &buffer, &offset, &max, 0);
    fix_digest_buffer(&buffer, &offset, &max, '\n');

    return buffer;
}

char *
dump_xml_formatted(xmlNode * an_xml_node)
{
    char *buffer = NULL;
    int offset = 0, max = 0;

    dump_xml(an_xml_node, xml_log_option_formatted, &buffer, &offset, &max, 0);
    return buffer;
}

char *
dump_xml_unformatted(xmlNode * an_xml_node)
{
    char *buffer = NULL;
    int offset = 0, max = 0;

    dump_xml(an_xml_node, 0, &buffer, &offset, &max, 0);
    return buffer;
}

gboolean
xml_has_children(const xmlNode * xml_root)
{
    if (xml_root != NULL && xml_root->children != NULL) {
        return TRUE;
    }
    return FALSE;
}

int
crm_element_value_int(xmlNode * data, const char *name, int *dest)
{
    const char *value = crm_element_value(data, name);

    CRM_CHECK(dest != NULL, return -1);
    if (value) {
        *dest = crm_int_helper(value, NULL);
        return 0;
    }
    return -1;
}

int
crm_element_value_const_int(const xmlNode * data, const char *name, int *dest)
{
    return crm_element_value_int((xmlNode *) data, name, dest);
}

const char *
crm_element_value_const(const xmlNode * data, const char *name)
{
    return crm_element_value((xmlNode *) data, name);
}

char *
crm_element_value_copy(xmlNode * data, const char *name)
{
    char *value_copy = NULL;
    const char *value = crm_element_value(data, name);

    if (value != NULL) {
        value_copy = strdup(value);
    }
    return value_copy;
}

void
xml_remove_prop(xmlNode * obj, const char *name)
{
    if(TRACKING_CHANGES(obj)) {
        /* Leave in place (marked for removal) until after the diff is calculated */
        xml_private_t *p = NULL;
        xmlAttr *attr = xmlHasProp(obj, (const xmlChar *)name);

        p = attr->_private;
        p->flags |= xpf_dirty|xpf_deleted;
        /* crm_trace("Setting flag %x due to %s[@id=%s].%s", xpf_dirty, obj->name, ID(obj), name); */

    } else {
        xmlUnsetProp(obj, (const xmlChar *)name);
    }
}

void
purge_diff_markers(xmlNode * a_node)
{
    xmlNode *child = NULL;

    CRM_CHECK(a_node != NULL, return);

    xml_remove_prop(a_node, XML_DIFF_MARKER);
    for (child = __xml_first_child(a_node); child != NULL; child = __xml_next(child)) {
        purge_diff_markers(child);
    }
}

void
save_xml_to_file(xmlNode * xml, const char *desc, const char *filename)
{
    char *f = NULL;

    if (filename == NULL) {
        char *uuid = crm_generate_uuid();

        f = g_strdup_printf("/tmp/%s", uuid);
        filename = f;
        free(uuid);
    }

    crm_info("Saving %s to %s", desc, filename);
    write_xml_file(xml, filename, FALSE);
    g_free(f);
}

gboolean
apply_xml_diff(xmlNode * old, xmlNode * diff, xmlNode ** new)
{
    gboolean result = TRUE;
    int root_nodes_seen = 0;
    static struct qb_log_callsite *digest_cs = NULL;
    const char *digest = crm_element_value(diff, XML_ATTR_DIGEST);
    const char *version = crm_element_value(diff, XML_ATTR_CRM_VERSION);

    xmlNode *child_diff = NULL;
    xmlNode *added = find_xml_node(diff, "diff-added", FALSE);
    xmlNode *removed = find_xml_node(diff, "diff-removed", FALSE);

    CRM_CHECK(new != NULL, return FALSE);
    if (digest_cs == NULL) {
        digest_cs =
            qb_log_callsite_get(__func__, __FILE__, "diff-digest", LOG_TRACE, __LINE__,
                                crm_trace_nonlog);
    }

    crm_trace("Substraction Phase");
    for (child_diff = __xml_first_child(removed); child_diff != NULL;
         child_diff = __xml_next(child_diff)) {
        CRM_CHECK(root_nodes_seen == 0, result = FALSE);
        if (root_nodes_seen == 0) {
            *new = subtract_xml_object(NULL, old, child_diff, FALSE, NULL, NULL);
        }
        root_nodes_seen++;
    }

    if (root_nodes_seen == 0) {
        *new = copy_xml(old);

    } else if (root_nodes_seen > 1) {
        crm_err("(-) Diffs cannot contain more than one change set..." " saw %d", root_nodes_seen);
        result = FALSE;
    }

    root_nodes_seen = 0;
    crm_trace("Addition Phase");
    if (result) {
        xmlNode *child_diff = NULL;

        for (child_diff = __xml_first_child(added); child_diff != NULL;
             child_diff = __xml_next(child_diff)) {
            CRM_CHECK(root_nodes_seen == 0, result = FALSE);
            if (root_nodes_seen == 0) {
                add_xml_object(NULL, *new, child_diff, TRUE);
            }
            root_nodes_seen++;
        }
    }

    if (root_nodes_seen > 1) {
        crm_err("(+) Diffs cannot contain more than one change set..." " saw %d", root_nodes_seen);
        result = FALSE;

    } else if (result && digest) {
        char *new_digest = NULL;

        purge_diff_markers(*new);       /* Purge now so the diff is ok */
        new_digest = calculate_xml_versioned_digest(*new, FALSE, TRUE, version);
        if (safe_str_neq(new_digest, digest)) {
            crm_info("Digest mis-match: expected %s, calculated %s", digest, new_digest);
            result = FALSE;

            crm_trace("%p %0.6x", digest_cs, digest_cs ? digest_cs->targets : 0);
            if (digest_cs && digest_cs->targets) {
                save_xml_to_file(old, "diff:original", NULL);
                save_xml_to_file(diff, "diff:input", NULL);
                save_xml_to_file(*new, "diff:new", NULL);
            }

        } else {
            crm_trace("Digest matched: expected %s, calculated %s", digest, new_digest);
        }
        free(new_digest);

    } else if (result) {
        purge_diff_markers(*new);       /* Purge now so the diff is ok */
    }

    return result;
}

static void
__xml_diff_object(xmlNode * old, xmlNode * new)
{
    xmlNode *cIter = NULL;
    xmlAttr *pIter = NULL;
    int insertions = 0;

    CRM_CHECK(new != NULL, return);
    if(old == NULL) {
        crm_node_created(new);
        return;

    } else {
        xml_private_t *p = new->_private;

        if(p->flags & xpf_processed) {
            /* Avoid re-comparing nodes */
            return;
        }
        p->flags |= xpf_processed;
    }

    for (pIter = crm_first_attr(new); pIter != NULL; pIter = pIter->next) {
        xml_private_t *p = pIter->_private;

        /* Assume everything was just created and take it from there */
        p->flags |= xpf_created;
    }

    for (pIter = crm_first_attr(old); pIter != NULL; pIter = pIter->next) {
        xml_private_t *p = NULL;
        const char *name = (const char *)pIter->name;
        const char *old_value = crm_element_value(old, name);
        xmlAttr *exists = xmlHasProp(new, pIter->name);

        if(exists == NULL) {
            exists = xmlSetProp(new, (const xmlChar *)name, (const xmlChar *)old_value);
            p = exists->_private;
            p->flags = (p->flags & ~xpf_created);
            xml_remove_prop(new, name);
            crm_trace("Lost %s@%s=%s %x %p", old->name, name, old_value, p->flags, p);

        } else {
            int p_new = __xml_offset((xmlNode*)exists);
            int p_old = __xml_offset((xmlNode*)pIter);
            const char *value = crm_element_value(new, name);

            p = exists->_private;
            p->flags = (p->flags & ~xpf_created);

            if(strcmp(value, old_value) != 0) {
                crm_trace("Modified %s@%s=%s", old->name, name, old_value);
                crm_attr_dirty(exists);

            } else if(p_old != p_new) {
                crm_info("Moved %s@%s (%d -> %d)", old->name, name, p_old, p_new);
                crm_attr_dirty(exists);
            }
        }
    }

    for (pIter = crm_first_attr(new); pIter != NULL; pIter = pIter->next) {
        xml_private_t *p = pIter->_private;

        if(is_set(p->flags, xpf_created)) {
            const char *name = (const char *)pIter->name;
            const char *value = crm_element_value(new, name);
            crm_trace("Created %s@%s=%s", new->name, name, value);
            crm_attr_dirty(pIter);
        }
    }

    for (cIter = __xml_first_child(old); cIter != NULL; cIter = __xml_next(cIter)) {
        xmlNode *new_child = find_entity(new, crm_element_name(cIter), ID(cIter));

        if(new_child) {
            __xml_diff_object(cIter, new_child);

        } else {
            int offset = 0;
            char buffer[XML_BUFFER_SIZE];
            xml_private_t *p = new->doc->_private;

            if(__get_prefix(NULL, cIter, buffer, offset) > 0) {
                p->deleted_paths = g_list_append(p->deleted_paths, strdup(buffer));
                /* crm_trace("Setting flag %x due to %s", xpf_dirty, buffer); */
                p->flags |= xpf_dirty;
            }

            p = old->_private;
            p->flags |= xpf_skip;
        }
    }

    for (cIter = __xml_first_child(new); cIter != NULL; cIter = __xml_next(cIter)) {
        xmlNode *old_child = find_entity(old, crm_element_name(cIter), ID(cIter));

        if(old_child == NULL) {
            insertions++;
            __xml_diff_object(old_child, cIter);

        } else {
            /* Check for movement, we already checked for differences */
            int p_new = __xml_offset(cIter);
            int p_old = __xml_offset(old_child);
            xml_private_t *p = cIter->_private;

            if(p_old != p_new - insertions) {
                crm_info("%s.%s moved from %d to %d - %d",
                         cIter->name, ID(cIter), p_old, p_new, insertions);
                p->flags |= xpf_moved;
            }
        }
    }
}

void
xml_calculate_changes(xmlNode * old, xmlNode * new)
{
    CRM_CHECK(safe_str_eq(crm_element_name(old), crm_element_name(new)), return);
    CRM_CHECK(safe_str_eq(ID(old), ID(new)), return);

    xml_track_changes(new);
    __xml_diff_object(old, new);
    xml_log_changes(LOG_TRACE, __FUNCTION__, new);
}

xmlNode *
diff_xml_object(xmlNode * old, xmlNode * new, gboolean suppress)
{
    xmlNode *tmp1 = NULL;
    xmlNode *diff = create_xml_node(NULL, "diff");
    xmlNode *removed = create_xml_node(diff, "diff-removed");
    xmlNode *added = create_xml_node(diff, "diff-added");

    crm_xml_add(diff, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);

    tmp1 = subtract_xml_object(removed, old, new, FALSE, NULL, "removed:top");
    if (suppress && tmp1 != NULL && can_prune_leaf(tmp1)) {
        free_xml(tmp1);
    }

    tmp1 = subtract_xml_object(added, new, old, TRUE, NULL, "added:top");
    if (suppress && tmp1 != NULL && can_prune_leaf(tmp1)) {
        free_xml(tmp1);
    }

    if (added->children == NULL && removed->children == NULL) {
        free_xml(diff);
        diff = NULL;
    }

    return diff;
}

gboolean
can_prune_leaf(xmlNode * xml_node)
{
    xmlNode *cIter = NULL;
    xmlAttrPtr pIter = NULL;
    gboolean can_prune = TRUE;

    for (pIter = crm_first_attr(xml_node); pIter != NULL; pIter = pIter->next) {
        const char *p_name = (const char *)pIter->name;

        if (strcmp(p_name, XML_ATTR_ID) == 0) {
            continue;
        }
        can_prune = FALSE;
    }

    cIter = __xml_first_child(xml_node);
    while (cIter) {
        xmlNode *child = cIter;

        cIter = __xml_next(cIter);
        if (can_prune_leaf(child)) {
            free_xml(child);
        } else {
            can_prune = FALSE;
        }
    }
    return can_prune;
}

void
diff_filter_context(int context, int upper_bound, int lower_bound,
                    xmlNode * xml_node, xmlNode * parent)
{
    xmlNode *us = NULL;
    xmlNode *child = NULL;
    xmlAttrPtr pIter = NULL;
    xmlNode *new_parent = parent;
    const char *name = crm_element_name(xml_node);

    CRM_CHECK(xml_node != NULL && name != NULL, return);

    us = create_xml_node(parent, name);
    for (pIter = crm_first_attr(xml_node); pIter != NULL; pIter = pIter->next) {
        const char *p_name = (const char *)pIter->name;
        const char *p_value = crm_attr_value(pIter);

        lower_bound = context;
        crm_xml_add(us, p_name, p_value);
    }

    if (lower_bound >= 0 || upper_bound >= 0) {
        crm_xml_add(us, XML_ATTR_ID, ID(xml_node));
        new_parent = us;

    } else {
        upper_bound = in_upper_context(0, context, xml_node);
        if (upper_bound >= 0) {
            crm_xml_add(us, XML_ATTR_ID, ID(xml_node));
            new_parent = us;
        } else {
            free_xml(us);
            us = NULL;
        }
    }

    for (child = __xml_first_child(us); child != NULL; child = __xml_next(child)) {
        diff_filter_context(context, upper_bound - 1, lower_bound - 1, child, new_parent);
    }
}

int
in_upper_context(int depth, int context, xmlNode * xml_node)
{
    if (context == 0) {
        return 0;
    }

    if (xml_node->properties) {
        return depth;

    } else if (depth < context) {
        xmlNode *child = NULL;

        for (child = __xml_first_child(xml_node); child != NULL; child = __xml_next(child)) {
            if (in_upper_context(depth + 1, context, child)) {
                return depth;
            }
        }
    }
    return 0;
}

static xmlNode *
find_xml_comment(xmlNode * root, xmlNode * search_comment)
{
    xmlNode *a_child = NULL;

    CRM_CHECK(search_comment->type == XML_COMMENT_NODE, return NULL);

    for (a_child = __xml_first_child(root); a_child != NULL; a_child = __xml_next(a_child)) {
        if (a_child->type != XML_COMMENT_NODE) {
            continue;
        }
        if (safe_str_eq((const char *)a_child->content, (const char *)search_comment->content)) {
            return a_child;
        }
    }

    return NULL;
}

static xmlNode *
subtract_xml_comment(xmlNode * parent, xmlNode * left, xmlNode * right,
                     gboolean * changed)
{
    CRM_CHECK(left != NULL, return NULL);
    CRM_CHECK(left->type == XML_COMMENT_NODE, return NULL);

    if (right == NULL
        || safe_str_neq((const char *)left->content, (const char *)right->content)) {
        xmlNode *deleted = NULL;

        deleted = add_node_copy(parent, left);
        *changed = TRUE;

        return deleted;
    }

    return NULL;
}

xmlNode *
subtract_xml_object(xmlNode * parent, xmlNode * left, xmlNode * right,
                    gboolean full, gboolean * changed, const char *marker)
{
    gboolean dummy = FALSE;
    gboolean skip = FALSE;
    xmlNode *diff = NULL;
    xmlNode *right_child = NULL;
    xmlNode *left_child = NULL;
    xmlAttrPtr xIter = NULL;

    const char *id = NULL;
    const char *name = NULL;
    const char *value = NULL;
    const char *right_val = NULL;

    int lpc = 0;
    static int filter_len = DIMOF(filter);

    if (changed == NULL) {
        changed = &dummy;
    }

    if (left == NULL) {
        return NULL;
    }

    if (left->type == XML_COMMENT_NODE) {
        return subtract_xml_comment(parent, left, right, changed);
    }

    id = ID(left);
    if (right == NULL) {
        xmlNode *deleted = NULL;

        crm_trace("Processing <%s id=%s> (complete copy)", crm_element_name(left), id);
        deleted = add_node_copy(parent, left);
        crm_xml_add(deleted, XML_DIFF_MARKER, marker);

        *changed = TRUE;
        return deleted;
    }

    name = crm_element_name(left);
    CRM_CHECK(name != NULL, return NULL);

    /* check for XML_DIFF_MARKER in a child */
    value = crm_element_value(right, XML_DIFF_MARKER);
    if (value != NULL && strcmp(value, "removed:top") == 0) {
        crm_trace("We are the root of the deletion: %s.id=%s", name, id);
        *changed = TRUE;
        return NULL;
    }

    /* Avoiding creating the full heirarchy would save even more work here */
    diff = create_xml_node(parent, name);

    /* Reset filter */
    for (lpc = 0; lpc < filter_len; lpc++) {
        filter[lpc].found = FALSE;
    }

    /* changes to child objects */
    for (left_child = __xml_first_child(left); left_child != NULL;
         left_child = __xml_next(left_child)) {
        gboolean child_changed = FALSE;

        if (left_child->type == XML_COMMENT_NODE) {
            right_child = find_xml_comment(right, left_child);

        } else {
            right_child = find_entity(right, crm_element_name(left_child), ID(left_child));
        }

        subtract_xml_object(diff, left_child, right_child, full, &child_changed, marker);
        if (child_changed) {
            *changed = TRUE;
        }
    }

    if (*changed == FALSE) {
        /* Nothing to do */

    } else if (full) {
        xmlAttrPtr pIter = NULL;

        for (pIter = crm_first_attr(left); pIter != NULL; pIter = pIter->next) {
            const char *p_name = (const char *)pIter->name;
            const char *p_value = crm_attr_value(pIter);

            xmlSetProp(diff, (const xmlChar *)p_name, (const xmlChar *)p_value);
        }

        /* We already have everything we need... */
        goto done;

    } else if (id) {
        xmlSetProp(diff, (const xmlChar *)XML_ATTR_ID, (const xmlChar *)id);
    }

    /* changes to name/value pairs */
    for (xIter = crm_first_attr(left); xIter != NULL; xIter = xIter->next) {
        const char *prop_name = (const char *)xIter->name;

        if (strcmp(prop_name, XML_ATTR_ID) == 0) {
            continue;
        }

        skip = FALSE;
        for (lpc = 0; skip == FALSE && lpc < filter_len; lpc++) {
            if (filter[lpc].found == FALSE && strcmp(prop_name, filter[lpc].string) == 0) {
                filter[lpc].found = TRUE;
                skip = TRUE;
                break;
            }
        }

        if (skip) {
            continue;
        }

        right_val = crm_element_value(right, prop_name);
        if (right_val == NULL) {
            /* new */
            *changed = TRUE;
            if (full) {
                xmlAttrPtr pIter = NULL;

                for (pIter = crm_first_attr(left); pIter != NULL; pIter = pIter->next) {
                    const char *p_name = (const char *)pIter->name;
                    const char *p_value = crm_attr_value(pIter);

                    xmlSetProp(diff, (const xmlChar *)p_name, (const xmlChar *)p_value);
                }
                break;

            } else {
                const char *left_value = crm_element_value(left, prop_name);

                xmlSetProp(diff, (const xmlChar *)prop_name, (const xmlChar *)value);
                crm_xml_add(diff, prop_name, left_value);
            }

        } else {
            /* Only now do we need the left value */
            const char *left_value = crm_element_value(left, prop_name);

            if (strcmp(left_value, right_val) == 0) {
                /* unchanged */

            } else {
                *changed = TRUE;
                if (full) {
                    xmlAttrPtr pIter = NULL;

                    crm_trace("Changes detected to %s in <%s id=%s>", prop_name,
                              crm_element_name(left), id);
                    for (pIter = crm_first_attr(left); pIter != NULL; pIter = pIter->next) {
                        const char *p_name = (const char *)pIter->name;
                        const char *p_value = crm_attr_value(pIter);

                        xmlSetProp(diff, (const xmlChar *)p_name, (const xmlChar *)p_value);
                    }
                    break;

                } else {
                    crm_trace("Changes detected to %s (%s -> %s) in <%s id=%s>",
                              prop_name, left_value, right_val, crm_element_name(left), id);
                    crm_xml_add(diff, prop_name, left_value);
                }
            }
        }
    }

    if (*changed == FALSE) {
        free_xml(diff);
        return NULL;

    } else if (full == FALSE && id) {
        crm_xml_add(diff, XML_ATTR_ID, id);
    }
  done:
    return diff;
}

static int
add_xml_comment(xmlNode * parent, xmlNode * target, xmlNode * update)
{
    CRM_CHECK(update != NULL, return 0);
    CRM_CHECK(update->type == XML_COMMENT_NODE, return 0);

    if (target == NULL) {
        target = find_xml_comment(parent, update);
    } 
    
    if (target == NULL) {
        add_node_copy(parent, update);

    /* We wont reach here currently */
    } else if (safe_str_neq((const char *)target->content, (const char *)update->content)) {
        xmlFree(target->content);
        target->content = xmlStrdup(update->content);
    }

    return 0;
}

int
add_xml_object(xmlNode * parent, xmlNode * target, xmlNode * update, gboolean as_diff)
{
    xmlNode *a_child = NULL;
    const char *object_id = NULL;
    const char *object_name = NULL;

#if XML_PARSE_DEBUG
    crm_log_xml_trace("update:", update);
    crm_log_xml_trace("target:", target);
#endif

    CRM_CHECK(update != NULL, return 0);

    if (update->type == XML_COMMENT_NODE) {
        return add_xml_comment(parent, target, update);
    }

    object_name = crm_element_name(update);
    object_id = ID(update);

    CRM_CHECK(object_name != NULL, return 0);

    if (target == NULL && object_id == NULL) {
        /*  placeholder object */
        target = find_xml_node(parent, object_name, FALSE);

    } else if (target == NULL) {
        target = find_entity(parent, object_name, object_id);
    }

    if (target == NULL) {
        target = create_xml_node(parent, object_name);
        CRM_CHECK(target != NULL, return 0);
#if XML_PARSER_DEBUG
        crm_trace("Added  <%s%s%s/>", crm_str(object_name),
                  object_id ? " id=" : "", object_id ? object_id : "");

    } else {
        crm_trace("Found node <%s%s%s/> to update",
                  crm_str(object_name), object_id ? " id=" : "", object_id ? object_id : "");
#endif
    }

    if (as_diff == FALSE) {
        /* So that expand_plus_plus() gets called */
        copy_in_properties(target, update);

    } else {
        /* No need for expand_plus_plus(), just raw speed */
        xmlAttrPtr pIter = NULL;

        for (pIter = crm_first_attr(update); pIter != NULL; pIter = pIter->next) {
            const char *p_name = (const char *)pIter->name;
            const char *p_value = crm_attr_value(pIter);

            /* Remove it first so the ordering of the update is preserved */
            xmlUnsetProp(target, (const xmlChar *)p_name);
            xmlSetProp(target, (const xmlChar *)p_name, (const xmlChar *)p_value);
        }
    }

    for (a_child = __xml_first_child(update); a_child != NULL; a_child = __xml_next(a_child)) {
#if XML_PARSER_DEBUG
        crm_trace("Updating child <%s id=%s>", crm_element_name(a_child), ID(a_child));
#endif
        add_xml_object(target, NULL, a_child, as_diff);
    }

#if XML_PARSER_DEBUG
    crm_trace("Finished with <%s id=%s>", crm_str(object_name), crm_str(object_id));
#endif
    return 0;
}

gboolean
update_xml_child(xmlNode * child, xmlNode * to_update)
{
    gboolean can_update = TRUE;
    xmlNode *child_of_child = NULL;

    CRM_CHECK(child != NULL, return FALSE);
    CRM_CHECK(to_update != NULL, return FALSE);

    if (safe_str_neq(crm_element_name(to_update), crm_element_name(child))) {
        can_update = FALSE;

    } else if (safe_str_neq(ID(to_update), ID(child))) {
        can_update = FALSE;

    } else if (can_update) {
#if XML_PARSER_DEBUG
        crm_log_xml_trace(child, "Update match found...");
#endif
        add_xml_object(NULL, child, to_update, FALSE);
    }

    for (child_of_child = __xml_first_child(child); child_of_child != NULL;
         child_of_child = __xml_next(child_of_child)) {
        /* only update the first one */
        if (can_update) {
            break;
        }
        can_update = update_xml_child(child_of_child, to_update);
    }

    return can_update;
}

int
find_xml_children(xmlNode ** children, xmlNode * root,
                  const char *tag, const char *field, const char *value, gboolean search_matches)
{
    int match_found = 0;

    CRM_CHECK(root != NULL, return FALSE);
    CRM_CHECK(children != NULL, return FALSE);

    if (tag != NULL && safe_str_neq(tag, crm_element_name(root))) {

    } else if (value != NULL && safe_str_neq(value, crm_element_value(root, field))) {

    } else {
        if (*children == NULL) {
            *children = create_xml_node(NULL, __FUNCTION__);
        }
        add_node_copy(*children, root);
        match_found = 1;
    }

    if (search_matches || match_found == 0) {
        xmlNode *child = NULL;

        for (child = __xml_first_child(root); child != NULL; child = __xml_next(child)) {
            match_found += find_xml_children(children, child, tag, field, value, search_matches);
        }
    }

    return match_found;
}

gboolean
replace_xml_child(xmlNode * parent, xmlNode * child, xmlNode * update, gboolean delete_only)
{
    gboolean can_delete = FALSE;
    xmlNode *child_of_child = NULL;

    const char *up_id = NULL;
    const char *child_id = NULL;
    const char *right_val = NULL;

    CRM_CHECK(child != NULL, return FALSE);
    CRM_CHECK(update != NULL, return FALSE);

    up_id = ID(update);
    child_id = ID(child);

    if (up_id == NULL || (child_id && strcmp(child_id, up_id) == 0)) {
        can_delete = TRUE;
    }
    if (safe_str_neq(crm_element_name(update), crm_element_name(child))) {
        can_delete = FALSE;
    }
    if (can_delete && delete_only) {
        xmlAttrPtr pIter = NULL;

        for (pIter = crm_first_attr(update); pIter != NULL; pIter = pIter->next) {
            const char *p_name = (const char *)pIter->name;
            const char *p_value = crm_attr_value(pIter);

            right_val = crm_element_value(child, p_name);
            if (safe_str_neq(p_value, right_val)) {
                can_delete = FALSE;
            }
        }
    }

    if (can_delete && parent != NULL) {
        crm_log_xml_trace(child, "Delete match found...");
        if (delete_only || update == NULL) {
            free_xml(child);

        } else {
            xmlNode *tmp = copy_xml(update);
            xmlDoc *doc = tmp->doc;
            xmlNode *old = xmlReplaceNode(child, tmp);

            free_xml(old);
            xmlDocSetRootElement(doc, NULL);
            xmlFreeDoc(doc);
        }
        child = NULL;
        return TRUE;

    } else if (can_delete) {
        crm_log_xml_debug(child, "Cannot delete the search root");
        can_delete = FALSE;
    }

    child_of_child = __xml_first_child(child);
    while (child_of_child) {
        xmlNode *next = __xml_next(child_of_child);

        can_delete = replace_xml_child(child, child_of_child, update, delete_only);

        /* only delete the first one */
        if (can_delete) {
            child_of_child = NULL;
        } else {
            child_of_child = next;
        }
    }

    return can_delete;
}

void
hash2nvpair(gpointer key, gpointer value, gpointer user_data)
{
    const char *name = key;
    const char *s_value = value;

    xmlNode *xml_node = user_data;
    xmlNode *xml_child = create_xml_node(xml_node, XML_CIB_TAG_NVPAIR);

    crm_xml_add(xml_child, XML_ATTR_ID, name);
    crm_xml_add(xml_child, XML_NVPAIR_ATTR_NAME, name);
    crm_xml_add(xml_child, XML_NVPAIR_ATTR_VALUE, s_value);

    crm_trace("dumped: name=%s value=%s", name, s_value);
}

void
hash2smartfield(gpointer key, gpointer value, gpointer user_data)
{
    const char *name = key;
    const char *s_value = value;

    xmlNode *xml_node = user_data;

    if (isdigit(name[0])) {
        xmlNode *tmp = create_xml_node(xml_node, XML_TAG_PARAM);

        crm_xml_add(tmp, XML_NVPAIR_ATTR_NAME, name);
        crm_xml_add(tmp, XML_NVPAIR_ATTR_VALUE, s_value);

    } else if (crm_element_value(xml_node, name) == NULL) {
        crm_xml_add(xml_node, name, s_value);
        crm_trace("dumped: %s=%s", name, s_value);

    } else {
        crm_trace("duplicate: %s=%s", name, s_value);
    }
}

void
hash2field(gpointer key, gpointer value, gpointer user_data)
{
    const char *name = key;
    const char *s_value = value;

    xmlNode *xml_node = user_data;

    if (crm_element_value(xml_node, name) == NULL) {
        crm_xml_add(xml_node, name, s_value);

    } else {
        crm_trace("duplicate: %s=%s", name, s_value);
    }
}

void
hash2metafield(gpointer key, gpointer value, gpointer user_data)
{
    char *crm_name = NULL;

    if (key == NULL || value == NULL) {
        return;
    } else if (((char *)key)[0] == '#') {
        return;
    } else if (strstr(key, ":")) {
        return;
    }

    crm_name = crm_meta_name(key);
    hash2field(crm_name, value, user_data);
    free(crm_name);
}

GHashTable *
xml2list(xmlNode * parent)
{
    xmlNode *child = NULL;
    xmlAttrPtr pIter = NULL;
    xmlNode *nvpair_list = NULL;
    GHashTable *nvpair_hash = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                                    g_hash_destroy_str, g_hash_destroy_str);

    CRM_CHECK(parent != NULL, return nvpair_hash);

    nvpair_list = find_xml_node(parent, XML_TAG_ATTRS, FALSE);
    if (nvpair_list == NULL) {
        crm_trace("No attributes in %s", crm_element_name(parent));
        crm_log_xml_trace(parent, "No attributes for resource op");
    }

    crm_log_xml_trace(nvpair_list, "Unpacking");

    for (pIter = crm_first_attr(nvpair_list); pIter != NULL; pIter = pIter->next) {
        const char *p_name = (const char *)pIter->name;
        const char *p_value = crm_attr_value(pIter);

        crm_trace("Added %s=%s", p_name, p_value);

        g_hash_table_insert(nvpair_hash, strdup(p_name), strdup(p_value));
    }

    for (child = __xml_first_child(nvpair_list); child != NULL; child = __xml_next(child)) {
        if (strcmp((const char *)child->name, XML_TAG_PARAM) == 0) {
            const char *key = crm_element_value(child, XML_NVPAIR_ATTR_NAME);
            const char *value = crm_element_value(child, XML_NVPAIR_ATTR_VALUE);

            crm_trace("Added %s=%s", key, value);
            if (key != NULL && value != NULL) {
                g_hash_table_insert(nvpair_hash, strdup(key), strdup(value));
            }
        }
    }

    return nvpair_hash;
}

typedef struct name_value_s {
    const char *name;
    const void *value;
} name_value_t;

static gint
sort_pairs(gconstpointer a, gconstpointer b)
{
    int rc = 0;
    const name_value_t *pair_a = a;
    const name_value_t *pair_b = b;

    CRM_ASSERT(a != NULL);
    CRM_ASSERT(pair_a->name != NULL);

    CRM_ASSERT(b != NULL);
    CRM_ASSERT(pair_b->name != NULL);

    rc = strcmp(pair_a->name, pair_b->name);
    if (rc < 0) {
        return -1;
    } else if (rc > 0) {
        return 1;
    }
    return 0;
}

static void
dump_pair(gpointer data, gpointer user_data)
{
    name_value_t *pair = data;
    xmlNode *parent = user_data;

    crm_xml_add(parent, pair->name, pair->value);
}

xmlNode *
sorted_xml(xmlNode * input, xmlNode * parent, gboolean recursive)
{
    xmlNode *child = NULL;
    GListPtr sorted = NULL;
    GListPtr unsorted = NULL;
    name_value_t *pair = NULL;
    xmlNode *result = NULL;
    const char *name = NULL;
    xmlAttrPtr pIter = NULL;

    CRM_CHECK(input != NULL, return NULL);

    name = crm_element_name(input);
    CRM_CHECK(name != NULL, return NULL);

    result = create_xml_node(parent, name);

    for (pIter = crm_first_attr(input); pIter != NULL; pIter = pIter->next) {
        const char *p_name = (const char *)pIter->name;
        const char *p_value = crm_attr_value(pIter);

        pair = calloc(1, sizeof(name_value_t));
        pair->name = p_name;
        pair->value = p_value;
        unsorted = g_list_prepend(unsorted, pair);
        pair = NULL;
    }

    sorted = g_list_sort(unsorted, sort_pairs);
    g_list_foreach(sorted, dump_pair, result);
    g_list_free_full(sorted, free);

    for (child = __xml_first_child(input); child != NULL; child = __xml_next(child)) {
        if (recursive) {
            sorted_xml(child, result, recursive);
        } else {
            add_node_copy(result, child);
        }
    }

    return result;
}

/* "c048eae664dba840e1d2060f00299e9d" */
static char *
calculate_xml_digest_v1(xmlNode * input, gboolean sort, gboolean ignored)
{
    char *digest = NULL;
    char *buffer = NULL;
    xmlNode *copy = NULL;

    if (sort) {
        crm_trace("Sorting xml...");
        copy = sorted_xml(input, NULL, TRUE);
        crm_trace("Done");
        input = copy;
    }

    buffer = dump_xml_for_digest(input);
    CRM_CHECK(buffer != NULL && strlen(buffer) > 0, free_xml(copy);
              free(buffer);
              return NULL);

    digest = crm_md5sum(buffer);
    crm_log_xml_trace(input, "digest:source");

    free(buffer);
    free_xml(copy);
    return digest;
}

static char *
calculate_xml_digest_v2(xmlNode * source, gboolean do_filter)
{
    char *digest = NULL;
    char *buffer = NULL;
    int offset, max;

    static struct qb_log_callsite *digest_cs = NULL;

    crm_trace("Begin digest %s", do_filter?"filtered":"");
    if (do_filter && BEST_EFFORT_STATUS) {
        /* Exclude the status calculation from the digest
         *
         * This doesn't mean it wont be sync'd, we just wont be paranoid
         * about it being an _exact_ copy
         *
         * We don't need it to be exact, since we throw it away and regenerate
         * from our peers whenever a new DC is elected anyway
         *
         * Importantly, this reduces the amount of XML to copy+export as
         * well as the amount of data for MD5 needs to operate on
         */

    } else {
        dump_xml(source, do_filter ? xml_log_option_filtered : 0, &buffer, &offset, &max, 0);
    }

    CRM_ASSERT(buffer != NULL);
    digest = crm_md5sum(buffer);

    if (digest_cs == NULL) {
        digest_cs = qb_log_callsite_get(__func__, __FILE__, "cib-digest", LOG_TRACE, __LINE__,
                                        crm_trace_nonlog);
    }
    if (digest_cs && digest_cs->targets) {
        char *trace_file = crm_concat("/tmp/cib-digest", digest, '-');

        crm_trace("Saving %s.%s.%s to %s",
                  crm_element_value(source, XML_ATTR_GENERATION_ADMIN),
                  crm_element_value(source, XML_ATTR_GENERATION),
                  crm_element_value(source, XML_ATTR_NUMUPDATES), trace_file);
        save_xml_to_file(source, "digest input", trace_file);
        free(trace_file);
    }

    free(buffer);
    crm_trace("End digest");
    return digest;
}

char *
calculate_on_disk_digest(xmlNode * input)
{
    /* Always use the v1 format for on-disk digests
     * a) its a compatability nightmare
     * b) we only use this once at startup, all other
     *    invocations are in a separate child process
     */
    return calculate_xml_digest_v1(input, FALSE, FALSE);
}

char *
calculate_operation_digest(xmlNode * input, const char *version)
{
    /* We still need the sorting for parameter digests */
    return calculate_xml_digest_v1(input, TRUE, FALSE);
}

char *
calculate_xml_versioned_digest(xmlNode * input, gboolean sort, gboolean do_filter,
                               const char *version)
{
    /*
     * The sorting associated with v1 digest creation accounted for 23% of
     * the CIB's CPU usage on the server. v2 drops this.
     *
     * The filtering accounts for an additional 2.5% and we may want to
     * remove it in future.
     *
     * v2 also uses the xmlBuffer contents directly to avoid additional copying
     */
    if (version == NULL || compare_version("3.0.5", version) > 0) {
        crm_trace("Using v1 digest algorithm for %s", crm_str(version));
        return calculate_xml_digest_v1(input, sort, do_filter);
    }
    crm_trace("Using v2 digest algorithm for %s", crm_str(version));
    return calculate_xml_digest_v2(input, do_filter);
}

static gboolean
validate_with_dtd(xmlDocPtr doc, gboolean to_logs, const char *dtd_file)
{
    gboolean valid = TRUE;

    xmlDtdPtr dtd = NULL;
    xmlValidCtxtPtr cvp = NULL;

    CRM_CHECK(doc != NULL, return FALSE);
    CRM_CHECK(dtd_file != NULL, return FALSE);

    dtd = xmlParseDTD(NULL, (const xmlChar *)dtd_file);
    if(dtd == NULL) {
        crm_err("Could not locate/parse DTD: %s", dtd_file);
        return TRUE;
    }

    cvp = xmlNewValidCtxt();
    if(cvp) {
        if (to_logs) {
            cvp->userData = (void *)LOG_ERR;
            cvp->error = (xmlValidityErrorFunc) xml_log;
            cvp->warning = (xmlValidityWarningFunc) xml_log;
        } else {
            cvp->userData = (void *)stderr;
            cvp->error = (xmlValidityErrorFunc) fprintf;
            cvp->warning = (xmlValidityWarningFunc) fprintf;
        }

        if (!xmlValidateDtd(cvp, doc, dtd)) {
            valid = FALSE;
        }
        xmlFreeValidCtxt(cvp);

    } else {
        crm_err("Internal error: No valid context");
    }

    xmlFreeDtd(dtd);
    return valid;
}

xmlNode *
first_named_child(xmlNode * parent, const char *name)
{
    xmlNode *match = NULL;

    for (match = __xml_first_child(parent); match != NULL; match = __xml_next(match)) {
        /*
         * name == NULL gives first child regardless of name; this is
         * semantically incorrect in this funciton, but may be necessary
         * due to prior use of xml_child_iter_filter
         */
        if (name == NULL || strcmp((const char *)match->name, name) == 0) {
            return match;
        }
    }
    return NULL;
}

#if 0
static void
relaxng_invalid_stderr(void *userData, xmlErrorPtr error)
{
    /*
       Structure xmlError
       struct _xmlError {
       int      domain  : What part of the library raised this er
       int      code    : The error code, e.g. an xmlParserError
       char *   message : human-readable informative error messag
       xmlErrorLevel    level   : how consequent is the error
       char *   file    : the filename
       int      line    : the line number if available
       char *   str1    : extra string information
       char *   str2    : extra string information
       char *   str3    : extra string information
       int      int1    : extra number information
       int      int2    : column number of the error or 0 if N/A
       void *   ctxt    : the parser context if available
       void *   node    : the node in the tree
       }
     */
    crm_err("Structured error: line=%d, level=%d %s", error->line, error->level, error->message);
}
#endif

static gboolean
validate_with_relaxng(xmlDocPtr doc, gboolean to_logs, const char *relaxng_file,
                      relaxng_ctx_cache_t ** cached_ctx)
{
    int rc = 0;
    gboolean valid = TRUE;
    relaxng_ctx_cache_t *ctx = NULL;

    CRM_CHECK(doc != NULL, return FALSE);
    CRM_CHECK(relaxng_file != NULL, return FALSE);

    if (cached_ctx && *cached_ctx) {
        ctx = *cached_ctx;

    } else {
        crm_info("Creating RNG parser context");
        ctx = calloc(1, sizeof(relaxng_ctx_cache_t));

        xmlLoadExtDtdDefaultValue = 1;
        ctx->parser = xmlRelaxNGNewParserCtxt(relaxng_file);
        CRM_CHECK(ctx->parser != NULL, goto cleanup);

        if (to_logs) {
            xmlRelaxNGSetParserErrors(ctx->parser,
                                      (xmlRelaxNGValidityErrorFunc) xml_log,
                                      (xmlRelaxNGValidityWarningFunc) xml_log,
                                      GUINT_TO_POINTER(LOG_ERR));
        } else {
            xmlRelaxNGSetParserErrors(ctx->parser,
                                      (xmlRelaxNGValidityErrorFunc) fprintf,
                                      (xmlRelaxNGValidityWarningFunc) fprintf, stderr);
        }

        ctx->rng = xmlRelaxNGParse(ctx->parser);
        CRM_CHECK(ctx->rng != NULL, crm_err("Could not find/parse %s", relaxng_file);
                  goto cleanup);

        ctx->valid = xmlRelaxNGNewValidCtxt(ctx->rng);
        CRM_CHECK(ctx->valid != NULL, goto cleanup);

        if (to_logs) {
            xmlRelaxNGSetValidErrors(ctx->valid,
                                     (xmlRelaxNGValidityErrorFunc) xml_log,
                                     (xmlRelaxNGValidityWarningFunc) xml_log,
                                     GUINT_TO_POINTER(LOG_ERR));
        } else {
            xmlRelaxNGSetValidErrors(ctx->valid,
                                     (xmlRelaxNGValidityErrorFunc) fprintf,
                                     (xmlRelaxNGValidityWarningFunc) fprintf, stderr);
        }
    }

    /* xmlRelaxNGSetValidStructuredErrors( */
    /*  valid, relaxng_invalid_stderr, valid); */

    xmlLineNumbersDefault(1);
    rc = xmlRelaxNGValidateDoc(ctx->valid, doc);
    if (rc > 0) {
        valid = FALSE;

    } else if (rc < 0) {
        crm_err("Internal libxml error during validation\n");
    }

  cleanup:

    if (cached_ctx) {
        *cached_ctx = ctx;

    } else {
        if (ctx->parser != NULL) {
            xmlRelaxNGFreeParserCtxt(ctx->parser);
        }
        if (ctx->valid != NULL) {
            xmlRelaxNGFreeValidCtxt(ctx->valid);
        }
        if (ctx->rng != NULL) {
            xmlRelaxNGFree(ctx->rng);
        }
        free(ctx);
    }

    return valid;
}

void
crm_xml_init(void)
{
    static bool init = TRUE;

    if(init) {
        init = FALSE;
        /* The default allocator XML_BUFFER_ALLOC_EXACT does far too many
         * realloc()s and it can take upwards of 18 seconds (yes, seconds)
         * to dump a 28kb tree which XML_BUFFER_ALLOC_DOUBLEIT can do in
         * less than 1 second.
         */
        xmlSetBufferAllocationScheme(XML_BUFFER_ALLOC_DOUBLEIT);

        /* Populate and free the _private field when nodes are created and destroyed */
        xmlDeregisterNodeDefault(pcmkDeregisterNode);
        xmlRegisterNodeDefault(pcmkRegisterNode);
    }
}

void
crm_xml_cleanup(void)
{
    int lpc = 0;
    relaxng_ctx_cache_t *ctx = NULL;

    crm_info("Cleaning up memory from libxml2");
    for (; lpc < all_schemas; lpc++) {
        switch (known_schemas[lpc].type) {
            case 0:
                /* None */
                break;
            case 1:
                /* DTD - Not cached */
                break;
            case 2:
                /* RNG - Cached */
                ctx = (relaxng_ctx_cache_t *) known_schemas[lpc].cache;
                if (ctx == NULL) {
                    break;
                }
                if (ctx->parser != NULL) {
                    xmlRelaxNGFreeParserCtxt(ctx->parser);
                }
                if (ctx->valid != NULL) {
                    xmlRelaxNGFreeValidCtxt(ctx->valid);
                }
                if (ctx->rng != NULL) {
                    xmlRelaxNGFree(ctx->rng);
                }
                free(ctx);
                known_schemas[lpc].cache = NULL;
                break;
            default:
                break;
        }
    }
    xsltCleanupGlobals();
    xmlCleanupParser();
}

static gboolean
validate_with(xmlNode * xml, int method, gboolean to_logs)
{
    xmlDocPtr doc = NULL;
    gboolean valid = FALSE;
    int type = known_schemas[method].type;
    char *file = NULL;

    CRM_CHECK(xml != NULL, return FALSE);
    doc = getDocPtr(xml);
    file = get_schema_path(known_schemas[method].location);

    crm_trace("Validating with: %s (type=%d)", crm_str(file), type);
    switch (type) {
        case 0:
            valid = TRUE;
            break;
        case 1:
            valid = validate_with_dtd(doc, to_logs, file);
            break;
        case 2:
            valid =
                validate_with_relaxng(doc, to_logs, file,
                                      (relaxng_ctx_cache_t **) & (known_schemas[method].cache));
            break;
        default:
            crm_err("Unknown validator type: %d", type);
            break;
    }

    free(file);
    return valid;
}

#include <stdio.h>
static void
dump_file(const char *filename)
{

    FILE *fp = NULL;
    int ch, line = 0;

    CRM_CHECK(filename != NULL, return);

    fp = fopen(filename, "r");
    CRM_CHECK(fp != NULL, return);

    fprintf(stderr, "%4d ", ++line);
    do {
        ch = getc(fp);
        if (ch == EOF) {
            putc('\n', stderr);
            break;
        } else if (ch == '\n') {
            fprintf(stderr, "\n%4d ", ++line);
        } else {
            putc(ch, stderr);
        }
    } while (1);

    fclose(fp);
}

gboolean
validate_xml_verbose(xmlNode * xml_blob)
{
    int fd = 0;
    xmlDoc *doc = NULL;
    xmlNode *xml = NULL;
    gboolean rc = FALSE;
    char *filename = strdup(CRM_STATE_DIR "/cib-invalid.XXXXXX");

    umask(S_IWGRP | S_IWOTH | S_IROTH);
    fd = mkstemp(filename);
    write_xml_fd(xml_blob, filename, fd, FALSE);

    dump_file(filename);

    doc = xmlParseFile(filename);
    xml = xmlDocGetRootElement(doc);
    rc = validate_xml(xml, NULL, FALSE);
    free_xml(xml);

    unlink(filename);

    return rc;
}

gboolean
validate_xml(xmlNode * xml_blob, const char *validation, gboolean to_logs)
{
    int lpc = 0;

    if (validation == NULL) {
        validation = crm_element_value(xml_blob, XML_ATTR_VALIDATION);
    }

    if (validation == NULL) {
        validation = crm_element_value(xml_blob, "ignore-dtd");
        if (crm_is_true(validation)) {
            validation = "none";
        } else {
            validation = "pacemaker-1.0";
        }
    }

    if (strcmp(validation, "none") == 0) {
        return TRUE;
    }

    for (; lpc < all_schemas; lpc++) {
        if (known_schemas[lpc].name && strcmp(validation, known_schemas[lpc].name) == 0) {
            return validate_with(xml_blob, lpc, to_logs);
        }
    }

    crm_err("Unknown validator: %s", validation);
    return FALSE;
}

#if HAVE_LIBXSLT
static xmlNode *
apply_transformation(xmlNode * xml, const char *transform)
{
    char *xform = NULL;
    xmlNode *out = NULL;
    xmlDocPtr res = NULL;
    xmlDocPtr doc = NULL;
    xsltStylesheet *xslt = NULL;

    CRM_CHECK(xml != NULL, return FALSE);
    doc = getDocPtr(xml);
    xform = get_schema_path(transform);

    xmlLoadExtDtdDefaultValue = 1;
    xmlSubstituteEntitiesDefault(1);

    xslt = xsltParseStylesheetFile((const xmlChar *)xform);
    CRM_CHECK(xslt != NULL, goto cleanup);

    res = xsltApplyStylesheet(xslt, doc, NULL);
    CRM_CHECK(res != NULL, goto cleanup);

    out = xmlDocGetRootElement(res);

  cleanup:
    if (xslt) {
        xsltFreeStylesheet(xslt);
    }

    free(xform);

    return out;
}
#endif

const char *
get_schema_name(int version)
{
    if (version < 0 || version >= all_schemas) {
        return "unknown";
    }
    return known_schemas[version].name;
}

int
get_schema_version(const char *name)
{
    int lpc = 0;

    for (; lpc < all_schemas; lpc++) {
        if (safe_str_eq(name, known_schemas[lpc].name)) {
            return lpc;
        }
    }
    return -1;
}

/* set which validation to use */
#include <crm/cib.h>
int
update_validation(xmlNode ** xml_blob, int *best, gboolean transform, gboolean to_logs)
{
    xmlNode *xml = NULL;
    char *value = NULL;
    int lpc = 0, match = -1, rc = pcmk_ok;

    CRM_CHECK(best != NULL, return -EINVAL);
    CRM_CHECK(xml_blob != NULL, return -EINVAL);
    CRM_CHECK(*xml_blob != NULL, return -EINVAL);

    *best = 0;
    xml = *xml_blob;
    value = crm_element_value_copy(xml, XML_ATTR_VALIDATION);

    if (value != NULL) {
        match = get_schema_version(value);

        lpc = match;
        if (lpc >= 0 && transform == FALSE) {
            lpc++;

        } else if (lpc < 0) {
            crm_debug("Unknown validation type");
            lpc = 0;
        }
    }

    if (match >= max_schemas) {
        /* nothing to do */
        free(value);
        *best = match;
        return pcmk_ok;
    }

    for (; lpc < max_schemas; lpc++) {
        gboolean valid = TRUE;

        crm_debug("Testing '%s' validation",
                  known_schemas[lpc].name ? known_schemas[lpc].name : "<unset>");
        valid = validate_with(xml, lpc, to_logs);

        if (valid) {
            *best = lpc;
        }

        if (valid && transform) {
            xmlNode *upgrade = NULL;
            int next = known_schemas[lpc].after_transform;

            if (next <= 0) {
                next = lpc + 1;
            }

            crm_notice("Upgrading %s-style configuration to %s with %s",
                       known_schemas[lpc].name, known_schemas[next].name,
                       known_schemas[lpc].transform ? known_schemas[lpc].transform : "no-op");

            if (known_schemas[lpc].transform == NULL) {
                if (validate_with(xml, next, to_logs)) {
                    crm_debug("Configuration valid for schema: %s", known_schemas[next].name);
                    lpc = next;
                    *best = next;
                    rc = pcmk_ok;

                } else {
                    crm_info("Configuration not valid for schema: %s", known_schemas[next].name);
                }

            } else {
#if HAVE_LIBXSLT
                upgrade = apply_transformation(xml, known_schemas[lpc].transform);
#endif
                if (upgrade == NULL) {
                    crm_err("Transformation %s failed", known_schemas[lpc].transform);
                    rc = -pcmk_err_transform_failed;

                } else if (validate_with(upgrade, next, to_logs)) {
                    crm_info("Transformation %s successful", known_schemas[lpc].transform);
                    lpc = next;
                    *best = next;
                    free_xml(xml);
                    xml = upgrade;
                    rc = pcmk_ok;

                } else {
                    crm_err("Transformation %s did not produce a valid configuration",
                            known_schemas[lpc].transform);
                    crm_log_xml_info(upgrade, "transform:bad");
                    free_xml(upgrade);
                    rc = -pcmk_err_dtd_validation;
                }
            }
        }
    }

    if (*best > match) {
        crm_notice("Upgraded from %s to %s validation", value ? value : "<none>",
                   known_schemas[*best].name);
        crm_xml_add(xml, XML_ATTR_VALIDATION, known_schemas[*best].name);
    }

    *xml_blob = xml;
    free(value);
    return rc;
}

/*
 * From xpath2.c
 *
 * All the elements returned by an XPath query are pointers to
 * elements from the tree *except* namespace nodes where the XPath
 * semantic is different from the implementation in libxml2 tree.
 * As a result when a returned node set is freed when
 * xmlXPathFreeObject() is called, that routine must check the
 * element type. But node from the returned set may have been removed
 * by xmlNodeSetContent() resulting in access to freed data.
 *
 * This can be exercised by running
 *       valgrind xpath2 test3.xml '//discarded' discarded
 *
 * There is 2 ways around it:
 *   - make a copy of the pointers to the nodes from the result set
 *     then call xmlXPathFreeObject() and then modify the nodes
 * or
 * - remove the references from the node set, if they are not
       namespace nodes, before calling xmlXPathFreeObject().
 */
void
freeXpathObject(xmlXPathObjectPtr xpathObj)
{
    int lpc, max = numXpathResults(xpathObj);

    if(xpathObj == NULL) {
        return;
    }

    for(lpc = 0; lpc < max; lpc++) {
        if (xpathObj->nodesetval->nodeTab[lpc] && xpathObj->nodesetval->nodeTab[lpc]->type != XML_NAMESPACE_DECL) {
            xpathObj->nodesetval->nodeTab[lpc] = NULL;
        }
    }

    /* _Now_ its safe to free it */
    xmlXPathFreeObject(xpathObj);
}

xmlNode *
getXpathResult(xmlXPathObjectPtr xpathObj, int index)
{
    xmlNode *match = NULL;
    int max = numXpathResults(xpathObj);

    CRM_CHECK(index >= 0, return NULL);
    CRM_CHECK(xpathObj != NULL, return NULL);

    if (index >= max) {
        crm_err("Requested index %d of only %d items", index, max);
        return NULL;

    } else if(xpathObj->nodesetval->nodeTab[index] == NULL) {
        /* Previously requested */
        return NULL;
    }

    match = xpathObj->nodesetval->nodeTab[index];
    CRM_CHECK(match != NULL, return NULL);

    if (xpathObj->nodesetval->nodeTab[index]->type != XML_NAMESPACE_DECL) {
        /* See the comment for freeXpathObject() */
        xpathObj->nodesetval->nodeTab[index] = NULL;
    }

    if (match->type == XML_DOCUMENT_NODE) {
        /* Will happen if section = '/' */
        match = match->children;

    } else if (match->type != XML_ELEMENT_NODE
               && match->parent && match->parent->type == XML_ELEMENT_NODE) {
        /* reurning the parent instead */
        match = match->parent;

    } else if (match->type != XML_ELEMENT_NODE) {
        /* We only support searching nodes */
        crm_err("We only support %d not %d", XML_ELEMENT_NODE, match->type);
        match = NULL;
    }
    return match;
}

/* the caller needs to check if the result contains a xmlDocPtr or xmlNodePtr */
xmlXPathObjectPtr
xpath_search(xmlNode * xml_top, const char *path)
{
    xmlDocPtr doc = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    const xmlChar *xpathExpr = (const xmlChar *)path;

    CRM_CHECK(path != NULL, return NULL);
    CRM_CHECK(xml_top != NULL, return NULL);
    CRM_CHECK(strlen(path) > 0, return NULL);

    doc = getDocPtr(xml_top);

    xpathCtx = xmlXPathNewContext(doc);
    CRM_ASSERT(xpathCtx != NULL);

    xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
    xmlXPathFreeContext(xpathCtx);
    return xpathObj;
}

gboolean
cli_config_update(xmlNode ** xml, int *best_version, gboolean to_logs)
{
    gboolean rc = TRUE;
    static int min_version = -1;
    static int max_version = -1;

    const char *value = crm_element_value(*xml, XML_ATTR_VALIDATION);
    int version = get_schema_version(value);

    if (min_version < 0) {
        min_version = get_schema_version(MINIMUM_SCHEMA_VERSION);
    }
    if (max_version < 0) {
        max_version = get_schema_version(LATEST_SCHEMA_VERSION);
    }

    if (version < min_version) {
        xmlNode *converted = NULL;

        converted = copy_xml(*xml);
        update_validation(&converted, &version, TRUE, to_logs);

        value = crm_element_value(converted, XML_ATTR_VALIDATION);
        if (version < min_version) {
            if (to_logs) {
                crm_config_err("Your current configuration could only be upgraded to %s... "
                               "the minimum requirement is %s.\n", crm_str(value),
                               MINIMUM_SCHEMA_VERSION);
            } else {
                fprintf(stderr, "Your current configuration could only be upgraded to %s... "
                        "the minimum requirement is %s.\n", crm_str(value), MINIMUM_SCHEMA_VERSION);
            }

            free_xml(converted);
            converted = NULL;
            rc = FALSE;

        } else {
            free_xml(*xml);
            *xml = converted;

            if (version < max_version) {
                crm_config_warn("Your configuration was internally updated to %s... "
                                "which is acceptable but not the most recent",
                                get_schema_name(version));

            } else if (to_logs) {
                crm_info("Your configuration was internally updated to the latest version (%s)",
                         get_schema_name(version));
            }
        }
    } else if (version > max_version) {
        if (to_logs) {
            crm_config_warn("Configuration validation is currently disabled."
                            " It is highly encouraged and prevents many common cluster issues.");

        } else {
            fprintf(stderr, "Configuration validation is currently disabled."
                    " It is highly encouraged and prevents many common cluster issues.\n");
        }
    }

    if (best_version) {
        *best_version = version;
    }

    return rc;
}

xmlNode *
expand_idref(xmlNode * input, xmlNode * top)
{
    const char *tag = NULL;
    const char *ref = NULL;
    xmlNode *result = input;
    char *xpath_string = NULL;

    if (result == NULL) {
        return NULL;

    } else if (top == NULL) {
        top = input;
    }

    tag = crm_element_name(result);
    ref = crm_element_value(result, XML_ATTR_IDREF);

    if (ref != NULL) {
        int xpath_max = 512, offset = 0;

        xpath_string = calloc(1, xpath_max);

        offset += snprintf(xpath_string + offset, xpath_max - offset, "//%s[@id='%s']", tag, ref);
        result = get_xpath_object(xpath_string, top, LOG_ERR);
        if (result == NULL) {
            char *nodePath = (char *)xmlGetNodePath(top);

            crm_err("No match for %s found in %s: Invalid configuration", xpath_string,
                    crm_str(nodePath));
            free(nodePath);
        }
    }

    free(xpath_string);
    return result;
}

xmlNode *
get_xpath_object_relative(const char *xpath, xmlNode * xml_obj, int error_level)
{
    int len = 0;
    xmlNode *result = NULL;
    char *xpath_full = NULL;
    char *xpath_prefix = NULL;

    if (xml_obj == NULL || xpath == NULL) {
        return NULL;
    }

    xpath_prefix = (char *)xmlGetNodePath(xml_obj);
    len += strlen(xpath_prefix);
    len += strlen(xpath);

    xpath_full = strdup(xpath_prefix);
    xpath_full = realloc(xpath_full, len + 1);
    strncat(xpath_full, xpath, len);

    result = get_xpath_object(xpath_full, xml_obj, error_level);

    free(xpath_prefix);
    free(xpath_full);
    return result;
}

xmlNode *
get_xpath_object(const char *xpath, xmlNode * xml_obj, int error_level)
{
    int max;
    xmlNode *result = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    char *nodePath = NULL;
    char *matchNodePath = NULL;

    if (xpath == NULL) {
        return xml_obj;         /* or return NULL? */
    }

    xpathObj = xpath_search(xml_obj, xpath);
    nodePath = (char *)xmlGetNodePath(xml_obj);
    max = numXpathResults(xpathObj);

    if (max < 1) {
        do_crm_log(error_level, "No match for %s in %s", xpath, crm_str(nodePath));
        crm_log_xml_explicit(xml_obj, "Unexpected Input");

    } else if (max > 1) {
        int lpc = 0;

        do_crm_log(error_level, "Too many matches for %s in %s", xpath, crm_str(nodePath));

        for (lpc = 0; lpc < max; lpc++) {
            xmlNode *match = getXpathResult(xpathObj, lpc);

            CRM_CHECK(match != NULL, continue);

            matchNodePath = (char *)xmlGetNodePath(match);
            do_crm_log(error_level, "%s[%d] = %s", xpath, lpc, crm_str(matchNodePath));
            free(matchNodePath);
        }
        crm_log_xml_explicit(xml_obj, "Bad Input");

    } else {
        result = getXpathResult(xpathObj, 0);
    }

    freeXpathObject(xpathObj);
    free(nodePath);

    return result;
}

const char *
crm_element_value(xmlNode * data, const char *name)
{
    xmlAttr *attr = NULL;

    if (data == NULL) {
        crm_err("Couldn't find %s in NULL", name ? name : "<null>");
        CRM_LOG_ASSERT(data != NULL);
        return NULL;

    } else if (name == NULL) {
        crm_err("Couldn't find NULL in %s", crm_element_name(data));
        return NULL;
    }

    attr = xmlHasProp(data, (const xmlChar *)name);
    if (attr == NULL || attr->children == NULL) {
        return NULL;
    }
    return (const char *)attr->children->content;
}

