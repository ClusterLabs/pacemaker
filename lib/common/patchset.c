/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <bzlib.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlIO.h>  /* xmlAllocOutputBuffer */

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>  // CRM_XML_LOG_BASE, etc.
#include "crmcommon_private.h"

static xmlNode *subtract_xml_comment(xmlNode *parent, xmlNode *left,
                                     xmlNode *right, gboolean *changed);

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
      <change-attr operation="set" name="description" value="some garbage here"/>
    </change-list>
    <change-result>
      <group id="g1" description="some garbage here"/><!-- NOTE: not recursive -->
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

// Add changes for specified XML to patchset
static void
add_xml_changes_to_patchset(xmlNode *xml, xmlNode *patchset)
{
    xmlNode *cIter = NULL;
    xmlAttr *pIter = NULL;
    xmlNode *change = NULL;
    xml_private_t *p = xml->_private;
    const char *value = NULL;

    // If this XML node is new, just report that
    if (patchset && pcmk_is_set(p->flags, xpf_created)) {
        int offset = 0;
        char buffer[PCMK__BUFFER_SIZE];

        if (pcmk__element_xpath(NULL, xml->parent, buffer, offset,
                                sizeof(buffer)) > 0) {
            int position = pcmk__xml_position(xml, xpf_deleted);

            change = create_xml_node(patchset, XML_DIFF_CHANGE);

            crm_xml_add(change, XML_DIFF_OP, "create");
            crm_xml_add(change, XML_DIFF_PATH, buffer);
            crm_xml_add_int(change, XML_DIFF_POSITION, position);
            add_node_copy(change, xml);
        }

        return;
    }

    // Check each of the XML node's attributes for changes
    for (pIter = pcmk__xe_first_attr(xml); pIter != NULL;
         pIter = pIter->next) {
        xmlNode *attr = NULL;

        p = pIter->_private;
        if (!pcmk_any_flags_set(p->flags, xpf_deleted|xpf_dirty)) {
            continue;
        }

        if (change == NULL) {
            int offset = 0;
            char buffer[PCMK__BUFFER_SIZE];

            if (pcmk__element_xpath(NULL, xml, buffer, offset,
                                    sizeof(buffer)) > 0) {
                change = create_xml_node(patchset, XML_DIFF_CHANGE);

                crm_xml_add(change, XML_DIFF_OP, "modify");
                crm_xml_add(change, XML_DIFF_PATH, buffer);

                change = create_xml_node(change, XML_DIFF_LIST);
            }
        }

        attr = create_xml_node(change, XML_DIFF_ATTR);

        crm_xml_add(attr, XML_NVPAIR_ATTR_NAME, (const char *)pIter->name);
        if (p->flags & xpf_deleted) {
            crm_xml_add(attr, XML_DIFF_OP, "unset");

        } else {
            crm_xml_add(attr, XML_DIFF_OP, "set");

            value = crm_element_value(xml, (const char *) pIter->name);
            crm_xml_add(attr, XML_NVPAIR_ATTR_VALUE, value);
        }
    }

    if (change) {
        xmlNode *result = NULL;

        change = create_xml_node(change->parent, XML_DIFF_RESULT);
        result = create_xml_node(change, (const char *)xml->name);

        for (pIter = pcmk__xe_first_attr(xml); pIter != NULL;
             pIter = pIter->next) {
            p = pIter->_private;
            if (!pcmk_is_set(p->flags, xpf_deleted)) {
                value = crm_element_value(xml, (const char *) pIter->name);
                crm_xml_add(result, (const char *)pIter->name, value);
            }
        }
    }

    // Now recursively do the same for each child node of this node
    for (cIter = pcmk__xml_first_child(xml); cIter != NULL;
         cIter = pcmk__xml_next(cIter)) {
        add_xml_changes_to_patchset(cIter, patchset);
    }

    p = xml->_private;
    if (patchset && pcmk_is_set(p->flags, xpf_moved)) {
        int offset = 0;
        char buffer[PCMK__BUFFER_SIZE];

        crm_trace("%s.%s moved to position %d",
                  xml->name, ID(xml), pcmk__xml_position(xml, xpf_skip));
        if (pcmk__element_xpath(NULL, xml, buffer, offset,
                                sizeof(buffer)) > 0) {
            change = create_xml_node(patchset, XML_DIFF_CHANGE);

            crm_xml_add(change, XML_DIFF_OP, "move");
            crm_xml_add(change, XML_DIFF_PATH, buffer);
            crm_xml_add_int(change, XML_DIFF_POSITION,
                            pcmk__xml_position(xml, xpf_deleted));
        }
    }
}

static bool
is_config_change(xmlNode *xml)
{
    GList *gIter = NULL;
    xml_private_t *p = NULL;
    xmlNode *config = first_named_child(xml, XML_CIB_TAG_CONFIGURATION);

    if (config) {
        p = config->_private;
    }
    if ((p != NULL) && pcmk_is_set(p->flags, xpf_dirty)) {
        return TRUE;
    }

    if ((xml->doc != NULL) && (xml->doc->_private != NULL)) {
        p = xml->doc->_private;
        for (gIter = p->deleted_objs; gIter; gIter = gIter->next) {
            pcmk__deleted_xml_t *deleted_obj = gIter->data;

            if (strstr(deleted_obj->path,
                       "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION) != NULL) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static void
xml_repair_v1_diff(xmlNode *last, xmlNode *next, xmlNode *local_diff,
                   gboolean changed)
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

    for (lpc = 0; (last != NULL) && (lpc < PCMK__NELEM(vfields)); lpc++) {
        const char *value = crm_element_value(last, vfields[lpc]);

        crm_xml_add(diff_child, vfields[lpc], value);
        if (changed || lpc == 2) {
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

    for (lpc = 0; next && lpc < PCMK__NELEM(vfields); lpc++) {
        const char *value = crm_element_value(next, vfields[lpc]);

        crm_xml_add(diff_child, vfields[lpc], value);
    }

    for (xmlAttrPtr a = pcmk__xe_first_attr(next); a != NULL; a = a->next) {
        const char *p_value = crm_element_value(next, (const char *) a->name);

        xmlSetProp(cib, a->name, (pcmkXmlStr) p_value);
    }

    crm_log_xml_explicit(local_diff, "Repaired-diff");
}

static xmlNode *
xml_create_patchset_v1(xmlNode *source, xmlNode *target, bool config,
                       bool suppress)
{
    xmlNode *patchset = diff_xml_object(source, target, suppress);

    if (patchset) {
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
    GList *gIter = NULL;
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
    if (!xml_document_dirty(target)) {
        return NULL;
    }

    CRM_ASSERT(target->doc);
    doc = target->doc->_private;

    patchset = create_xml_node(NULL, XML_TAG_DIFF);
    crm_xml_add_int(patchset, "format", 2);

    version = create_xml_node(patchset, XML_DIFF_VERSION);

    v = create_xml_node(version, XML_DIFF_VSOURCE);
    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        const char *value = crm_element_value(source, vfields[lpc]);

        if (value == NULL) {
            value = "1";
        }
        crm_xml_add(v, vfields[lpc], value);
    }

    v = create_xml_node(version, XML_DIFF_VTARGET);
    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        const char *value = crm_element_value(target, vfields[lpc]);

        if (value == NULL) {
            value = "1";
        }
        crm_xml_add(v, vfields[lpc], value);
    }

    for (gIter = doc->deleted_objs; gIter; gIter = gIter->next) {
        pcmk__deleted_xml_t *deleted_obj = gIter->data;
        xmlNode *change = create_xml_node(patchset, XML_DIFF_CHANGE);

        crm_xml_add(change, XML_DIFF_OP, "delete");
        crm_xml_add(change, XML_DIFF_PATH, deleted_obj->path);
        if (deleted_obj->position >= 0) {
            crm_xml_add_int(change, XML_DIFF_POSITION, deleted_obj->position);
        }
    }

    add_xml_changes_to_patchset(target, patchset);
    return patchset;
}

xmlNode *
xml_create_patchset(int format, xmlNode *source, xmlNode *target,
                    bool *config_changed, bool manage_version)
{
    int counter = 0;
    bool config = FALSE;
    xmlNode *patch = NULL;
    const char *version = crm_element_value(source, XML_ATTR_CRM_VERSION);

    xml_acl_disable(target);
    if (!xml_document_dirty(target)) {
        crm_trace("No change %d", format);
        return NULL; /* No change */
    }

    config = is_config_change(target);
    if (config_changed) {
        *config_changed = config;
    }

    if (manage_version && config) {
        crm_trace("Config changed %d", format);
        crm_xml_add(target, XML_ATTR_NUMUPDATES, "0");

        crm_element_value_int(target, XML_ATTR_GENERATION, &counter);
        crm_xml_add_int(target, XML_ATTR_GENERATION, counter+1);

    } else if (manage_version) {
        crm_element_value_int(target, XML_ATTR_NUMUPDATES, &counter);
        crm_trace("Status changed %d - %d %s", format, counter,
                  crm_element_value(source, XML_ATTR_NUMUPDATES));
        crm_xml_add_int(target, XML_ATTR_NUMUPDATES, (counter + 1));
    }

    if (format == 0) {
        if (compare_version("3.0.8", version) < 0) {
            format = 2;
        } else {
            format = 1;
        }
        crm_trace("Using patch format %d for version: %s", format, version);
    }

    switch (format) {
        case 1:
            patch = xml_create_patchset_v1(source, target, config, FALSE);
            break;
        case 2:
            patch = xml_create_patchset_v2(source, target);
            break;
        default:
            crm_err("Unknown patch format: %d", format);
            return NULL;
    }
    return patch;
}

void
patchset_process_digest(xmlNode *patch, xmlNode *source, xmlNode *target,
                        bool with_digest)
{
    int format = 1;
    const char *version = NULL;
    char *digest = NULL;

    if ((patch == NULL) || (source == NULL) || (target == NULL)) {
        return;
    }

    /* We should always call xml_accept_changes() before calculating a digest.
     * Otherwise, with an on-tracking dirty target, we could get a wrong digest.
     */
    CRM_LOG_ASSERT(!xml_document_dirty(target));

    crm_element_value_int(patch, "format", &format);
    if ((format > 1) && !with_digest) {
        return;
    }

    version = crm_element_value(source, XML_ATTR_CRM_VERSION);
    digest = calculate_xml_versioned_digest(target, FALSE, TRUE, version);

    crm_xml_add(patch, XML_ATTR_DIGEST, digest);
    free(digest);

    return;
}

void
xml_log_patchset(uint8_t log_level, const char *function, xmlNode *patchset)
{
    int format = 1;
    xmlNode *child = NULL;
    xmlNode *added = NULL;
    xmlNode *removed = NULL;
    gboolean is_first = TRUE;

    int add[] = { 0, 0, 0 };
    int del[] = { 0, 0, 0 };

    const char *fmt = NULL;
    const char *digest = NULL;
    int options = xml_log_option_formatted;

    static struct qb_log_callsite *patchset_cs = NULL;

    if (log_level == LOG_NEVER) {
        return;
    }
    if (patchset_cs == NULL) {
        patchset_cs = qb_log_callsite_get(function, __FILE__, "xml-patchset",
                                          log_level, __LINE__, 0);
    }

    if (patchset == NULL) {
        crm_trace("Empty patch");
        return;

    } else if ((log_level != LOG_STDOUT)
               && !crm_is_callsite_active(patchset_cs, log_level, 0)) {
        return;
    }

    xml_patch_versions(patchset, add, del);
    fmt = crm_element_value(patchset, "format");
    digest = crm_element_value(patchset, XML_ATTR_DIGEST);

    if ((add[2] != del[2]) || (add[1] != del[1]) || (add[0] != del[0])) {
        do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                         "Diff: --- %d.%d.%d %s", del[0], del[1], del[2], fmt);
        do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                         "Diff: +++ %d.%d.%d %s",
                         add[0], add[1], add[2], digest);

    } else if ((patchset != NULL) && (add[0] || add[1] || add[2])) {
        do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                         "%s: Local-only Change: %d.%d.%d",
                         (function? function : ""), add[0], add[1], add[2]);
    }

    crm_element_value_int(patchset, "format", &format);
    if (format == 2) {
        xmlNode *change = NULL;

        for (change = pcmk__xml_first_child(patchset); change != NULL;
             change = pcmk__xml_next(change)) {
            const char *op = crm_element_value(change, XML_DIFF_OP);
            const char *xpath = crm_element_value(change, XML_DIFF_PATH);

            if (op == NULL) {
            } else if (strcmp(op, "create") == 0) {
                int lpc = 0, max = 0;
                char *prefix = crm_strdup_printf("++ %s: ", xpath);

                max = strlen(prefix);
                pcmk__xe_log(log_level, __FILE__, function, __LINE__, prefix,
                             change->children, 0,
                             xml_log_option_formatted|xml_log_option_open);

                for (lpc = 2; lpc < max; lpc++) {
                    prefix[lpc] = ' ';
                }

                pcmk__xe_log(log_level, __FILE__, function, __LINE__, prefix,
                             change->children, 0,
                             xml_log_option_formatted|xml_log_option_close
                                |xml_log_option_children);
                free(prefix);

            } else if (strcmp(op, "move") == 0) {
                do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                                 "+~ %s moved to offset %s", xpath,
                                 crm_element_value(change, XML_DIFF_POSITION));

            } else if (strcmp(op, "modify") == 0) {
                xmlNode *clist = first_named_child(change, XML_DIFF_LIST);
                char buffer_set[PCMK__BUFFER_SIZE];
                char buffer_unset[PCMK__BUFFER_SIZE];
                int o_set = 0;
                int o_unset = 0;

                buffer_set[0] = 0;
                buffer_unset[0] = 0;
                for (child = pcmk__xml_first_child(clist); child != NULL;
                     child = pcmk__xml_next(child)) {
                    const char *name = crm_element_value(child, "name");

                    op = crm_element_value(child, XML_DIFF_OP);
                    if (op == NULL) {
                    } else if (strcmp(op, "set") == 0) {
                        const char *value = crm_element_value(child, "value");

                        if (o_set > 0) {
                            o_set += snprintf(buffer_set + o_set,
                                              PCMK__BUFFER_SIZE - o_set, ", ");
                        }
                        o_set += snprintf(buffer_set + o_set,
                                          PCMK__BUFFER_SIZE - o_set, "@%s=%s",
                                          name, value);

                    } else if (strcmp(op, "unset") == 0) {
                        if (o_unset > 0) {
                            o_unset += snprintf(buffer_unset + o_unset,
                                                PCMK__BUFFER_SIZE - o_unset,
                                                ", ");
                        }
                        o_unset += snprintf(buffer_unset + o_unset,
                                            PCMK__BUFFER_SIZE - o_unset, "@%s",
                                            name);
                    }
                }
                if (o_set) {
                    do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                                     "+  %s:  %s", xpath, buffer_set);
                }
                if (o_unset) {
                    do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                                     "-- %s:  %s", xpath, buffer_unset);
                }

            } else if (strcmp(op, "delete") == 0) {
                int position = -1;

                crm_element_value_int(change, XML_DIFF_POSITION, &position);
                if (position >= 0) {
                    do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                                     "-- %s (%d)", xpath, position);

                } else {
                    do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                                     "-- %s", xpath);
                }
            }
        }
        return;
    }

    if ((log_level < LOG_DEBUG) || (function == NULL)) {
        options |= xml_log_option_diff_short;
    }

    removed = find_xml_node(patchset, "diff-removed", FALSE);
    for (child = pcmk__xml_first_child(removed); child != NULL;
         child = pcmk__xml_next(child)) {
        log_data_element(log_level, __FILE__, function, __LINE__, "- ", child,
                         0, options|xml_log_option_diff_minus);
        if (is_first) {
            is_first = FALSE;
        } else {
            do_crm_log_alias(log_level, __FILE__, function, __LINE__, " --- ");
        }
    }

    is_first = TRUE;
    added = find_xml_node(patchset, "diff-added", FALSE);
    for (child = pcmk__xml_first_child(added); child != NULL;
         child = pcmk__xml_next(child)) {
        log_data_element(log_level, __FILE__, function, __LINE__, "+ ", child,
                         0, options|xml_log_option_diff_plus);
        if (is_first) {
            is_first = FALSE;
        } else {
            do_crm_log_alias(log_level, __FILE__, function, __LINE__, " +++ ");
        }
    }
}

// Return true if attribute name is not "id"
static bool
not_id(xmlAttrPtr attr, void *user_data)
{
    return strcmp((const char *) attr->name, XML_ATTR_ID) != 0;
}

// Apply the removals section of an v1 patchset to an XML node
static void
process_v1_removals(xmlNode *target, xmlNode *patch)
{
    xmlNode *patch_child = NULL;
    xmlNode *cIter = NULL;

    char *id = NULL;
    const char *name = NULL;
    const char *value = NULL;

    if ((target == NULL) || (patch == NULL)) {
        return;
    }

    if (target->type == XML_COMMENT_NODE) {
        gboolean dummy;

        subtract_xml_comment(target->parent, target, patch, &dummy);
    }

    name = crm_element_name(target);
    CRM_CHECK(name != NULL, return);
    CRM_CHECK(pcmk__str_eq(crm_element_name(target), crm_element_name(patch),
                           pcmk__str_casei),
              return);
    CRM_CHECK(pcmk__str_eq(ID(target), ID(patch), pcmk__str_casei), return);

    // Check for XML_DIFF_MARKER in a child
    id = crm_element_value_copy(target, XML_ATTR_ID);
    value = crm_element_value(patch, XML_DIFF_MARKER);
    if ((value != NULL) && (strcmp(value, "removed:top") == 0)) {
        crm_trace("We are the root of the deletion: %s.id=%s", name, id);
        free_xml(target);
        free(id);
        return;
    }

    // Removing then restoring id would change ordering of properties
    pcmk__xe_remove_matching_attrs(patch, not_id, NULL);

    // Changes to child objects
    cIter = pcmk__xml_first_child(target);
    while (cIter) {
        xmlNode *target_child = cIter;

        cIter = pcmk__xml_next(cIter);
        patch_child = pcmk__xml_match(patch, target_child, false);
        process_v1_removals(target_child, patch_child);
    }
    free(id);
}

// Apply the additions section of an v1 patchset to an XML node
static void
process_v1_additions(xmlNode *parent, xmlNode *target, xmlNode *patch)
{
    xmlNode *patch_child = NULL;
    xmlNode *target_child = NULL;
    xmlAttrPtr xIter = NULL;

    const char *id = NULL;
    const char *name = NULL;
    const char *value = NULL;

    if (patch == NULL) {
        return;
    } else if ((parent == NULL) && (target == NULL)) {
        return;
    }

    // Check for XML_DIFF_MARKER in a child
    value = crm_element_value(patch, XML_DIFF_MARKER);
    if ((target == NULL) && (value != NULL)
        && (strcmp(value, "added:top") == 0)) {
        id = ID(patch);
        name = crm_element_name(patch);
        crm_trace("We are the root of the addition: %s.id=%s", name, id);
        add_node_copy(parent, patch);
        return;

    } else if (target == NULL) {
        id = ID(patch);
        name = crm_element_name(patch);
        crm_err("Could not locate: %s.id=%s", name, id);
        return;
    }

    if (target->type == XML_COMMENT_NODE) {
        pcmk__xc_update(parent, target, patch);
    }

    name = crm_element_name(target);
    CRM_CHECK(name != NULL, return);
    CRM_CHECK(pcmk__str_eq(crm_element_name(target), crm_element_name(patch),
                           pcmk__str_casei),
              return);
    CRM_CHECK(pcmk__str_eq(ID(target), ID(patch), pcmk__str_casei), return);

    for (xIter = pcmk__xe_first_attr(patch); xIter != NULL;
         xIter = xIter->next) {
        const char *p_name = (const char *) xIter->name;
        const char *p_value = crm_element_value(patch, p_name);

        xml_remove_prop(target, p_name); // Preserve patch order
        crm_xml_add(target, p_name, p_value);
    }

    // Changes to child objects
    for (patch_child = pcmk__xml_first_child(patch); patch_child != NULL;
         patch_child = pcmk__xml_next(patch_child)) {

        target_child = pcmk__xml_match(target, patch_child, false);
        process_v1_additions(target, target_child, patch_child);
    }
}

/*!
 * \internal
 * \brief Find additions or removals in a patch set
 *
 * \param[in]     patchset   XML of patch
 * \param[in]     format     Patch version
 * \param[in]     added      TRUE if looking for additions, FALSE if removals
 * \param[in,out] patch_node Will be set to node if found
 *
 * \return TRUE if format is valid, FALSE if invalid
 */
static bool
find_patch_xml_node(xmlNode *patchset, int format, bool added,
                    xmlNode **patch_node)
{
    xmlNode *cib_node;
    const char *label;

    switch (format) {
        case 1:
            label = added? "diff-added" : "diff-removed";
            *patch_node = find_xml_node(patchset, label, FALSE);
            cib_node = find_xml_node(*patch_node, "cib", FALSE);
            if (cib_node != NULL) {
                *patch_node = cib_node;
            }
            break;
        case 2:
            label = added? "target" : "source";
            *patch_node = find_xml_node(patchset, "version", FALSE);
            *patch_node = find_xml_node(*patch_node, label, FALSE);
            break;
        default:
            crm_warn("Unknown patch format: %d", format);
            *patch_node = NULL;
            return FALSE;
    }
    return TRUE;
}

// Get CIB versions used for additions and deletions in a patchset
bool
xml_patch_versions(xmlNode *patchset, int add[3], int del[3])
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

    /* Process removals */
    if (!find_patch_xml_node(patchset, format, FALSE, &tmp)) {
        return -EINVAL;
    }
    if (tmp != NULL) {
        for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
            crm_element_value_int(tmp, vfields[lpc], &(del[lpc]));
            crm_trace("Got %d for del[%s]", del[lpc], vfields[lpc]);
        }
    }

    /* Process additions */
    if (!find_patch_xml_node(patchset, format, TRUE, &tmp)) {
        return -EINVAL;
    }
    if (tmp != NULL) {
        for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
            crm_element_value_int(tmp, vfields[lpc], &(add[lpc]));
            crm_trace("Got %d for add[%s]", add[lpc], vfields[lpc]);
        }
    }
    return pcmk_ok;
}

/*!
 * \internal
 * \brief Check whether patchset can be applied to current CIB
 *
 * \param[in] xml       Root of current CIB
 * \param[in] patchset  Patchset to check
 * \param[in] format    Patchset version
 *
 * \return Standard Pacemaker return code
 */
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

    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        crm_element_value_int(xml, vfields[lpc], &(this[lpc]));
        crm_trace("Got %d for this[%s]", this[lpc], vfields[lpc]);
        if (this[lpc] < 0) {
            this[lpc] = 0;
        }
    }

    /* Set some defaults in case nothing is present */
    add[0] = this[0];
    add[1] = this[1];
    add[2] = this[2] + 1;
    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        del[lpc] = this[lpc];
    }

    xml_patch_versions(patchset, add, del);

    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        if (this[lpc] < del[lpc]) {
            crm_debug("Current %s is too low (%d.%d.%d < %d.%d.%d --> %d.%d.%d)",
                      vfields[lpc], this[0], this[1], this[2],
                      del[0], del[1], del[2], add[0], add[1], add[2]);
            return pcmk_rc_diff_resync;

        } else if (this[lpc] > del[lpc]) {
            crm_info("Current %s is too high (%d.%d.%d > %d.%d.%d --> %d.%d.%d) %p",
                     vfields[lpc], this[0], this[1], this[2],
                     del[0], del[1], del[2], add[0], add[1], add[2], patchset);
            crm_log_xml_info(patchset, "OldPatch");
            return pcmk_rc_old_data;
        }
    }

    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        if (add[lpc] > del[lpc]) {
            changed = TRUE;
        }
    }

    if (!changed) {
        crm_notice("Versions did not change in patch %d.%d.%d",
                   add[0], add[1], add[2]);
        return pcmk_rc_old_data;
    }

    crm_debug("Can apply patch %d.%d.%d to %d.%d.%d",
              add[0], add[1], add[2], this[0], this[1], this[2]);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Apply a version 1 patchset to an XML node
 *
 * \param[in,out] xml       XML to apply patchset to
 * \param[in]     patchset  Patchset to apply
 *
 * \return Standard Pacemaker return code
 */
static int
apply_v1_patchset(xmlNode *xml, xmlNode *patchset)
{
    int rc = pcmk_rc_ok;
    int root_nodes_seen = 0;

    xmlNode *child_diff = NULL;
    xmlNode *added = find_xml_node(patchset, "diff-added", FALSE);
    xmlNode *removed = find_xml_node(patchset, "diff-removed", FALSE);
    xmlNode *old = copy_xml(xml);

    crm_trace("Subtraction Phase");
    for (child_diff = pcmk__xml_first_child(removed); child_diff != NULL;
         child_diff = pcmk__xml_next(child_diff)) {
        CRM_CHECK(root_nodes_seen == 0, rc = FALSE);
        if (root_nodes_seen == 0) {
            process_v1_removals(xml, child_diff);
        }
        root_nodes_seen++;
    }

    if (root_nodes_seen > 1) {
        crm_err("(-) Diffs cannot contain more than one change set... saw %d",
                root_nodes_seen);
        rc = ENOTUNIQ;
    }

    root_nodes_seen = 0;
    crm_trace("Addition Phase");
    if (rc == pcmk_rc_ok) {
        xmlNode *child_diff = NULL;

        for (child_diff = pcmk__xml_first_child(added); child_diff != NULL;
             child_diff = pcmk__xml_next(child_diff)) {
            CRM_CHECK(root_nodes_seen == 0, rc = FALSE);
            if (root_nodes_seen == 0) {
                process_v1_additions(NULL, xml, child_diff);
            }
            root_nodes_seen++;
        }
    }

    if (root_nodes_seen > 1) {
        crm_err("(+) Diffs cannot contain more than one change set... saw %d",
                root_nodes_seen);
        rc = ENOTUNIQ;
    }

    purge_diff_markers(xml); // Purge prior to checking digest

    free_xml(old);
    return rc;
}

// Return first child matching element name and optionally id or position
static xmlNode *
first_matching_xml_child(xmlNode *parent, const char *name, const char *id,
                         int position)
{
    xmlNode *cIter = NULL;

    for (cIter = pcmk__xml_first_child(parent); cIter != NULL;
         cIter = pcmk__xml_next(cIter)) {
        if (strcmp((const char *) cIter->name, name) != 0) {
            continue;
        } else if (id) {
            const char *cid = ID(cIter);

            if ((cid == NULL) || (strcmp(cid, id) != 0)) {
                continue;
            }
        }

        // "position" makes sense only for XML comments for now
        if ((cIter->type == XML_COMMENT_NODE)
            && (position >= 0)
            && (pcmk__xml_position(cIter, xpf_skip) != position)) {
            continue;
        }

        return cIter;
    }
    return NULL;
}

/*!
 * \internal
 * \brief Simplified, more efficient alternative to get_xpath_object()
 *
 * \param[in] top              Root of XML to search
 * \param[in] key              Search xpath
 * \param[in] target_position  If deleting, where to delete
 *
 * \return XML child matching xpath if found, NULL otherwise
 *
 * \note This only works on simplified xpaths found in v2 patchset diffs,
 *       i.e. the only allowed search predicate is [@id='XXX'].
 */
static xmlNode *
search_v2_xpath(xmlNode *top, const char *key, int target_position)
{
    xmlNode *target = (xmlNode *) top->doc;
    const char *current = key;
    char *section;
    char *remainder;
    char *id;
    char *tag;
    char *path = NULL;
    int rc;
    size_t key_len;

    CRM_CHECK(key != NULL, return NULL);
    key_len = strlen(key);

    /* These are scanned from key after a slash, so they can't be bigger
     * than key_len - 1 characters plus a null terminator.
     */

    remainder = calloc(key_len, sizeof(char));
    CRM_ASSERT(remainder != NULL);

    section = calloc(key_len, sizeof(char));
    CRM_ASSERT(section != NULL);

    id = calloc(key_len, sizeof(char));
    CRM_ASSERT(id != NULL);

    tag = calloc(key_len, sizeof(char));
    CRM_ASSERT(tag != NULL);

    do {
        // Look for /NEXT_COMPONENT/REMAINING_COMPONENTS
        rc = sscanf(current, "/%[^/]%s", section, remainder);
        if (rc > 0) {
            // Separate FIRST_COMPONENT into TAG[@id='ID']
            int f = sscanf(section, "%[^[][@id='%[^']", tag, id);
            int current_position = -1;

            /* The target position is for the final component tag, so only use
             * it if there is nothing left to search after this component.
             */
            if ((rc == 1) && (target_position >= 0)) {
                current_position = target_position;
            }

            switch (f) {
                case 1:
                    target = first_matching_xml_child(target, tag, NULL,
                                                      current_position);
                    break;
                case 2:
                    target = first_matching_xml_child(target, tag, id,
                                                      current_position);
                    break;
                default:
                    // This should not be possible
                    target = NULL;
                    break;
            }
            current = remainder;
        }

    // Continue if something remains to search, and we've matched so far
    } while ((rc == 2) && target);

    if (target) {
        crm_trace("Found %s for %s",
                  (path = (char *) xmlGetNodePath(target)), key);
        free(path);
    } else {
        crm_debug("No match for %s", key);
    }

    free(remainder);
    free(section);
    free(tag);
    free(id);
    return target;
}

typedef struct xml_change_obj_s {
    xmlNode *change;
    xmlNode *match;
} xml_change_obj_t;

static gint
sort_change_obj_by_position(gconstpointer a, gconstpointer b)
{
    const xml_change_obj_t *change_obj_a = a;
    const xml_change_obj_t *change_obj_b = b;
    int position_a = -1;
    int position_b = -1;

    crm_element_value_int(change_obj_a->change, XML_DIFF_POSITION, &position_a);
    crm_element_value_int(change_obj_b->change, XML_DIFF_POSITION, &position_b);

    if (position_a < position_b) {
        return -1;

    } else if (position_a > position_b) {
        return 1;
    }

    return 0;
}

/*!
 * \internal
 * \brief Apply a version 2 patchset to an XML node
 *
 * \param[in,out] xml       XML to apply patchset to
 * \param[in]     patchset  Patchset to apply
 *
 * \return Standard Pacemaker return code
 */
static int
apply_v2_patchset(xmlNode *xml, xmlNode *patchset)
{
    int rc = pcmk_rc_ok;
    xmlNode *change = NULL;
    GList *change_objs = NULL;
    GList *gIter = NULL;

    for (change = pcmk__xml_first_child(patchset); change != NULL;
         change = pcmk__xml_next(change)) {
        xmlNode *match = NULL;
        const char *op = crm_element_value(change, XML_DIFF_OP);
        const char *xpath = crm_element_value(change, XML_DIFF_PATH);
        int position = -1;

        if (op == NULL) {
            continue;
        }

        crm_trace("Processing %s %s", change->name, op);

        // "delete" changes for XML comments are generated with "position"
        if (strcmp(op, "delete") == 0) {
            crm_element_value_int(change, XML_DIFF_POSITION, &position);
        }
        match = search_v2_xpath(xml, xpath, position);
        crm_trace("Performing %s on %s with %p", op, xpath, match);

        if ((match == NULL) && (strcmp(op, "delete") == 0)) {
            crm_debug("No %s match for %s in %p", op, xpath, xml->doc);
            continue;

        } else if (match == NULL) {
            crm_err("No %s match for %s in %p", op, xpath, xml->doc);
            rc = pcmk_rc_diff_failed;
            continue;

        } else if ((strcmp(op, "create") == 0) || (strcmp(op, "move") == 0)) {
            // Delay the adding of a "create" object
            xml_change_obj_t *change_obj = calloc(1, sizeof(xml_change_obj_t));

            CRM_ASSERT(change_obj != NULL);

            change_obj->change = change;
            change_obj->match = match;

            change_objs = g_list_append(change_objs, change_obj);

            if (strcmp(op, "move") == 0) {
                // Temporarily put the "move" object after the last sibling
                if ((match->parent != NULL) && (match->parent->last != NULL)) {
                    xmlAddNextSibling(match->parent->last, match);
                }
            }

        } else if (strcmp(op, "delete") == 0) {
            free_xml(match);

        } else if (strcmp(op, "modify") == 0) {
            xmlNode *attrs = NULL;

            attrs = pcmk__xml_first_child(first_named_child(change,
                                                            XML_DIFF_RESULT));
            if (attrs == NULL) {
                rc = ENOMSG;
                continue;
            }
            pcmk__xe_remove_matching_attrs(match, NULL, NULL); // Remove all

            for (xmlAttrPtr pIter = pcmk__xe_first_attr(attrs); pIter != NULL;
                 pIter = pIter->next) {
                const char *name = (const char *) pIter->name;
                const char *value = crm_element_value(attrs, name);

                crm_xml_add(match, name, value);
            }

        } else {
            crm_err("Unknown operation: %s", op);
            rc = pcmk_rc_diff_failed;
        }
    }

    // Changes should be generated in the right order. Double checking.
    change_objs = g_list_sort(change_objs, sort_change_obj_by_position);

    for (gIter = change_objs; gIter; gIter = gIter->next) {
        xml_change_obj_t *change_obj = gIter->data;
        xmlNode *match = change_obj->match;
        const char *op = NULL;
        const char *xpath = NULL;

        change = change_obj->change;

        op = crm_element_value(change, XML_DIFF_OP);
        xpath = crm_element_value(change, XML_DIFF_PATH);

        crm_trace("Continue performing %s on %s with %p", op, xpath, match);

        if (strcmp(op, "create") == 0) {
            int position = 0;
            xmlNode *child = NULL;
            xmlNode *match_child = NULL;

            match_child = match->children;
            crm_element_value_int(change, XML_DIFF_POSITION, &position);

            while ((match_child != NULL)
                   && (position != pcmk__xml_position(match_child, xpf_skip))) {
                match_child = match_child->next;
            }

            child = xmlDocCopyNode(change->children, match->doc, 1);
            if (match_child) {
                crm_trace("Adding %s at position %d", child->name, position);
                xmlAddPrevSibling(match_child, child);

            } else if (match->last) {
                crm_trace("Adding %s at position %d (end)",
                          child->name, position);
                xmlAddNextSibling(match->last, child);

            } else {
                crm_trace("Adding %s at position %d (first)",
                          child->name, position);
                CRM_LOG_ASSERT(position == 0);
                xmlAddChild(match, child);
            }
            pcmk__mark_xml_created(child);

        } else if (strcmp(op, "move") == 0) {
            int position = 0;

            crm_element_value_int(change, XML_DIFF_POSITION, &position);
            if (position != pcmk__xml_position(match, xpf_skip)) {
                xmlNode *match_child = NULL;
                int p = position;

                if (p > pcmk__xml_position(match, xpf_skip)) {
                    p++; // Skip ourselves
                }

                CRM_ASSERT(match->parent != NULL);
                match_child = match->parent->children;

                while ((match_child != NULL)
                       && (p != pcmk__xml_position(match_child, xpf_skip))) {
                    match_child = match_child->next;
                }

                crm_trace("Moving %s to position %d (was %d, prev %p, %s %p)",
                          match->name, position,
                          pcmk__xml_position(match, xpf_skip),
                          match->prev, (match_child? "next":"last"),
                          (match_child? match_child : match->parent->last));

                if (match_child) {
                    xmlAddPrevSibling(match_child, match);

                } else {
                    CRM_ASSERT(match->parent->last != NULL);
                    xmlAddNextSibling(match->parent->last, match);
                }

            } else {
                crm_trace("%s is already in position %d",
                          match->name, position);
            }

            if (position != pcmk__xml_position(match, xpf_skip)) {
                crm_err("Moved %s.%s to position %d instead of %d (%p)",
                        match->name, ID(match),
                        pcmk__xml_position(match, xpf_skip),
                        position, match->prev);
                rc = pcmk_rc_diff_failed;
            }
        }
    }

    g_list_free_full(change_objs, free);
    return rc;
}

int
xml_apply_patchset(xmlNode *xml, xmlNode *patchset, bool check_version)
{
    int format = 1;
    int rc = pcmk_ok;
    xmlNode *old = NULL;
    const char *digest = crm_element_value(patchset, XML_ATTR_DIGEST);

    if (patchset == NULL) {
        return rc;
    }

    xml_log_patchset(LOG_TRACE, __func__, patchset);

    crm_element_value_int(patchset, "format", &format);
    if (check_version) {
        rc = pcmk_rc2legacy(xml_patch_version_check(xml, patchset, format));
        if (rc != pcmk_ok) {
            return rc;
        }
    }

    if (digest) {
        // Make it available for logging if result doesn't have expected digest
        old = copy_xml(xml);
    }

    if (rc == pcmk_ok) {
        switch (format) {
            case 1:
                rc = pcmk_rc2legacy(apply_v1_patchset(xml, patchset));
                break;
            case 2:
                rc = pcmk_rc2legacy(apply_v2_patchset(xml, patchset));
                break;
            default:
                crm_err("Unknown patch format: %d", format);
                rc = -EINVAL;
        }
    }

    if ((rc == pcmk_ok) && (digest != NULL)) {
        static struct qb_log_callsite *digest_cs = NULL;

        char *new_digest = NULL;
        char *version = crm_element_value_copy(xml, XML_ATTR_CRM_VERSION);

        if (digest_cs == NULL) {
            digest_cs = qb_log_callsite_get(__func__, __FILE__, "diff-digest",
                                            LOG_TRACE, __LINE__,
                                            crm_trace_nonlog);
        }

        new_digest = calculate_xml_versioned_digest(xml, FALSE, TRUE, version);
        if (!pcmk__str_eq(new_digest, digest, pcmk__str_casei)) {
            crm_info("v%d digest mis-match: expected %s, calculated %s",
                     format, digest, new_digest);
            rc = -pcmk_err_diff_failed;

            if ((digest_cs != NULL) && digest_cs->targets) {
                save_xml_to_file(old,      "PatchDigest:input",  NULL);
                save_xml_to_file(xml,      "PatchDigest:result", NULL);
                save_xml_to_file(patchset, "PatchDigest:diff",   NULL);

            } else {
                crm_trace("%p %.6x", digest_cs,
                          ((digest_cs != NULL)? digest_cs->targets : 0));
            }

        } else {
            crm_trace("v%d digest matched: expected %s, calculated %s",
                      format, digest, new_digest);
        }
        free(new_digest);
        free(version);
    }
    free_xml(old);
    return rc;
}

void
purge_diff_markers(xmlNode *a_node)
{
    xmlNode *child = NULL;

    CRM_CHECK(a_node != NULL, return);

    xml_remove_prop(a_node, XML_DIFF_MARKER);
    for (child = pcmk__xml_first_child(a_node); child != NULL;
         child = pcmk__xml_next(child)) {
        purge_diff_markers(child);
    }
}

xmlNode *
diff_xml_object(xmlNode *old, xmlNode *new, gboolean suppress)
{
    xmlNode *tmp1 = NULL;
    xmlNode *diff = create_xml_node(NULL, "diff");
    xmlNode *removed = create_xml_node(diff, "diff-removed");
    xmlNode *added = create_xml_node(diff, "diff-added");

    crm_xml_add(diff, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);

    tmp1 = subtract_xml_object(removed, old, new, FALSE, NULL, "removed:top");
    if (suppress && (tmp1 != NULL) && can_prune_leaf(tmp1)) {
        free_xml(tmp1);
    }

    tmp1 = subtract_xml_object(added, new, old, TRUE, NULL, "added:top");
    if (suppress && (tmp1 != NULL) && can_prune_leaf(tmp1)) {
        free_xml(tmp1);
    }

    if ((added->children == NULL) && (removed->children == NULL)) {
        free_xml(diff);
        diff = NULL;
    }

    return diff;
}

static xmlNode *
subtract_xml_comment(xmlNode *parent, xmlNode *left, xmlNode *right,
                     gboolean *changed)
{
    CRM_CHECK(left != NULL, return NULL);
    CRM_CHECK(left->type == XML_COMMENT_NODE, return NULL);

    if ((right == NULL) || !pcmk__str_eq((const char *)left->content,
                                         (const char *)right->content,
                                         pcmk__str_casei)) {
        xmlNode *deleted = NULL;

        deleted = add_node_copy(parent, left);
        *changed = TRUE;

        return deleted;
    }

    return NULL;
}

xmlNode *
subtract_xml_object(xmlNode *parent, xmlNode *left, xmlNode *right,
                    gboolean full, gboolean *changed, const char *marker)
{
    gboolean dummy = FALSE;
    xmlNode *diff = NULL;
    xmlNode *right_child = NULL;
    xmlNode *left_child = NULL;
    xmlAttrPtr xIter = NULL;

    const char *id = NULL;
    const char *name = NULL;
    const char *value = NULL;
    const char *right_val = NULL;

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

        crm_trace("Processing <%s id=%s> (complete copy)",
                  crm_element_name(left), id);
        deleted = add_node_copy(parent, left);
        crm_xml_add(deleted, XML_DIFF_MARKER, marker);

        *changed = TRUE;
        return deleted;
    }

    name = crm_element_name(left);
    CRM_CHECK(name != NULL, return NULL);
    CRM_CHECK(pcmk__str_eq(crm_element_name(left), crm_element_name(right),
                           pcmk__str_casei),
              return NULL);

    // Check for XML_DIFF_MARKER in a child
    value = crm_element_value(right, XML_DIFF_MARKER);
    if ((value != NULL) && (strcmp(value, "removed:top") == 0)) {
        crm_trace("We are the root of the deletion: %s.id=%s", name, id);
        *changed = TRUE;
        return NULL;
    }

    // @TODO Avoiding creating the full hierarchy would save work here
    diff = create_xml_node(parent, name);

    // Changes to child objects
    for (left_child = pcmk__xml_first_child(left); left_child != NULL;
         left_child = pcmk__xml_next(left_child)) {
        gboolean child_changed = FALSE;

        right_child = pcmk__xml_match(right, left_child, false);
        subtract_xml_object(diff, left_child, right_child, full, &child_changed,
                            marker);
        if (child_changed) {
            *changed = TRUE;
        }
    }

    if (!*changed) {
        /* Nothing to do */

    } else if (full) {
        xmlAttrPtr pIter = NULL;

        for (pIter = pcmk__xe_first_attr(left); pIter != NULL;
             pIter = pIter->next) {
            const char *p_name = (const char *)pIter->name;
            const char *p_value = pcmk__xml_attr_value(pIter);

            xmlSetProp(diff, (pcmkXmlStr) p_name, (pcmkXmlStr) p_value);
        }

        // We have everything we need
        goto done;
    }

    // Changes to name/value pairs
    for (xIter = pcmk__xe_first_attr(left); xIter != NULL;
         xIter = xIter->next) {
        const char *prop_name = (const char *) xIter->name;
        xmlAttrPtr right_attr = NULL;
        xml_private_t *p = NULL;

        if (strcmp(prop_name, XML_ATTR_ID) == 0) {
            // id already obtained when present ~ this case, so just reuse
            xmlSetProp(diff, (pcmkXmlStr) XML_ATTR_ID, (pcmkXmlStr) id);
            continue;
        }

        if (pcmk__xa_filterable(prop_name)) {
            continue;
        }

        right_attr = xmlHasProp(right, (pcmkXmlStr) prop_name);
        if (right_attr) {
            p = right_attr->_private;
        }

        right_val = crm_element_value(right, prop_name);
        if ((right_val == NULL) || (p && pcmk_is_set(p->flags, xpf_deleted))) {
            /* new */
            *changed = TRUE;
            if (full) {
                xmlAttrPtr pIter = NULL;

                for (pIter = pcmk__xe_first_attr(left); pIter != NULL;
                     pIter = pIter->next) {
                    const char *p_name = (const char *) pIter->name;
                    const char *p_value = pcmk__xml_attr_value(pIter);

                    xmlSetProp(diff, (pcmkXmlStr) p_name, (pcmkXmlStr) p_value);
                }
                break;

            } else {
                const char *left_value = crm_element_value(left, prop_name);

                xmlSetProp(diff, (pcmkXmlStr) prop_name, (pcmkXmlStr) value);
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
                    for (pIter = pcmk__xe_first_attr(left); pIter != NULL;
                         pIter = pIter->next) {
                        const char *p_name = (const char *) pIter->name;
                        const char *p_value = pcmk__xml_attr_value(pIter);

                        xmlSetProp(diff, (pcmkXmlStr) p_name,
                                   (pcmkXmlStr) p_value);
                    }
                    break;

                } else {
                    crm_trace("Changes detected to %s (%s -> %s) in <%s id=%s>",
                              prop_name, left_value, right_val,
                              crm_element_name(left), id);
                    crm_xml_add(diff, prop_name, left_value);
                }
            }
        }
    }

    if (!*changed) {
        free_xml(diff);
        return NULL;

    } else if (!full && (id != NULL)) {
        crm_xml_add(diff, XML_ATTR_ID, id);
    }
  done:
    return diff;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/xml_compat.h>

gboolean
apply_xml_diff(xmlNode *old_xml, xmlNode *diff, xmlNode **new_xml)
{
    gboolean result = TRUE;
    int root_nodes_seen = 0;
    static struct qb_log_callsite *digest_cs = NULL;
    const char *digest = crm_element_value(diff, XML_ATTR_DIGEST);
    const char *version = crm_element_value(diff, XML_ATTR_CRM_VERSION);

    xmlNode *child_diff = NULL;
    xmlNode *added = find_xml_node(diff, "diff-added", FALSE);
    xmlNode *removed = find_xml_node(diff, "diff-removed", FALSE);

    CRM_CHECK(new_xml != NULL, return FALSE);
    if (digest_cs == NULL) {
        digest_cs = qb_log_callsite_get(__func__, __FILE__, "diff-digest",
                                        LOG_TRACE, __LINE__, crm_trace_nonlog);
    }

    crm_trace("Subtraction Phase");
    for (child_diff = pcmk__xml_first_child(removed); child_diff != NULL;
         child_diff = pcmk__xml_next(child_diff)) {
        CRM_CHECK(root_nodes_seen == 0, result = FALSE);
        if (root_nodes_seen == 0) {
            *new_xml = subtract_xml_object(NULL, old_xml, child_diff, FALSE,
                                           NULL, NULL);
        }
        root_nodes_seen++;
    }

    if (root_nodes_seen == 0) {
        *new_xml = copy_xml(old_xml);

    } else if (root_nodes_seen > 1) {
        crm_err("(-) Diffs cannot contain more than one change set... saw %d",
                root_nodes_seen);
        result = FALSE;
    }

    root_nodes_seen = 0;
    crm_trace("Addition Phase");
    if (result) {
        xmlNode *child_diff = NULL;

        for (child_diff = pcmk__xml_first_child(added); child_diff != NULL;
             child_diff = pcmk__xml_next(child_diff)) {
            CRM_CHECK(root_nodes_seen == 0, result = FALSE);
            if (root_nodes_seen == 0) {
                pcmk__xml_update(NULL, *new_xml, child_diff, true);
            }
            root_nodes_seen++;
        }
    }

    if (root_nodes_seen > 1) {
        crm_err("(+) Diffs cannot contain more than one change set... saw %d",
                root_nodes_seen);
        result = FALSE;

    } else if (result && (digest != NULL)) {
        char *new_digest = NULL;

        purge_diff_markers(*new_xml); // Purge now so diff is ok
        new_digest = calculate_xml_versioned_digest(*new_xml, FALSE, TRUE,
                                                    version);
        if (!pcmk__str_eq(new_digest, digest, pcmk__str_casei)) {
            crm_info("Digest mis-match: expected %s, calculated %s",
                     digest, new_digest);
            result = FALSE;

            crm_trace("%p %.6x", digest_cs, digest_cs ? digest_cs->targets : 0);
            if ((digest_cs != NULL) && digest_cs->targets) {
                save_xml_to_file(old_xml, "diff:original", NULL);
                save_xml_to_file(diff, "diff:input", NULL);
                save_xml_to_file(*new_xml, "diff:new", NULL);
            }

        } else {
            crm_trace("Digest matched: expected %s, calculated %s",
                      digest, new_digest);
        }
        free(new_digest);

    } else if (result) {
        purge_diff_markers(*new_xml); // Purge now so diff is ok
    }

    return result;
}

// LCOV_EXCL_STOP
// End deprecated API
