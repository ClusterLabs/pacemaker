/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/pengine/internal.h>

int
pe__name_and_nvpairs_xml(pcmk__output_t *out, bool is_list, const char *tag_name
                         , size_t pairs_count, ...)
{ 
    xmlNodePtr xml_node = NULL;
    va_list args;

    CRM_ASSERT(tag_name != NULL);

    xml_node = pcmk__xml_peek_parent(out);
    CRM_ASSERT(xml_node != NULL);
    xml_node = is_list
        ? create_xml_node(xml_node, tag_name)
        : xmlNewChild(xml_node, NULL, (pcmkXmlStr) tag_name, NULL);

    va_start(args, pairs_count);
    while(pairs_count--) {
        const char *param_name = va_arg(args, const char *);
        const char *param_value = va_arg(args, const char *);
        if (param_name && param_value) {
            xmlSetProp(xml_node, (pcmkXmlStr)param_name, (pcmkXmlStr)param_value);
        }
    };
    va_end(args);

    if (is_list) {
        pcmk__xml_push_parent(out, xml_node);
    }
    return 0;
}

static int
pe__group_xml(pcmk__output_t *out, va_list args)
{
    long options = va_arg(args, long);
    resource_t *rsc = va_arg(args, resource_t *);

    GListPtr gIter = rsc->children;
    char *count = crm_itoa(g_list_length(gIter));

    int rc = pe__name_and_nvpairs_xml(out, true, "group", 2
                                      , "id", rsc->id
                                      , "number_resources", count);
    free(count);
    CRM_ASSERT(rc == 0);

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        out->message(out, crm_element_name(child_rsc->xml), options, child_rsc);
    }

    pcmk__xml_pop_parent(out);
    return rc;
}

static pcmk__message_entry_t fmt_functions[] = {
    { "bundle", "xml",  pe__bundle_xml },
    { "clone", "xml",  pe__clone_xml },
    { "group", "xml",  pe__group_xml },
    { "primitive", "xml",  pe__resource_xml },
    
    { NULL, NULL, NULL }
};

void
pe__register_messages(pcmk__output_t *out) {
    static bool registered = FALSE;

    if (!registered) {
        pcmk__register_messages(out, fmt_functions);
        registered = TRUE;
    }
}

void
pe__output_node(node_t *node, gboolean details, pcmk__output_t *out)
{
    if (node == NULL) {
        crm_trace("<NULL>");
        return;
    }

    CRM_ASSERT(node->details);
    crm_trace("%sNode %s: (weight=%d, fixed=%s)",
              node->details->online ? "" : "Unavailable/Unclean ",
              node->details->uname, node->weight, node->fixed ? "True" : "False");

    if (details) {
        char *pe_mutable = strdup("\t\t");
        GListPtr gIter = node->details->running_rsc;

        crm_trace("\t\t===Node Attributes");
        g_hash_table_foreach(node->details->attrs, print_str_str, pe_mutable);
        free(pe_mutable);

        crm_trace("\t\t=== Resources");

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *rsc = (resource_t *) gIter->data;

            pe__output_resource(LOG_TRACE, rsc, FALSE, out);
        }
    }
}

void
pe__output_resource(int log_level, resource_t *rsc, gboolean details, pcmk__output_t  *out)
{
    long options = pe_print_log | pe_print_pending;

    if (rsc == NULL) {
        do_crm_log(log_level - 1, "<NULL>");
        return;
    }
    if (details) {
        options |= pe_print_details;
    }
    out->message(out, crm_element_name(rsc->xml), options, rsc);
}
