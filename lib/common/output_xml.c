/*
 * Copyright 2019-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <crm/crm.h>

#include <glib.h>
#include <libxml/tree.h>                    // xmlNode
#include <libxml/xmlstring.h>               // xmlChar

#include <crm/common/output.h>
#include <crm/common/xml.h>

typedef struct subst_s {
    const char *from;
    const char *to;
} subst_t;

static const subst_t substitutions[] = {
    { "Active Resources",
      PCMK_XE_RESOURCES, },
    { "Assignment Scores",
      PCMK_XE_ALLOCATIONS, },
    { "Assignment Scores and Utilization Information",
      PCMK_XE_ALLOCATIONS_UTILIZATIONS, },
    { "Cluster Summary",
      PCMK_XE_SUMMARY, },
    { "Current cluster status",
      PCMK_XE_CLUSTER_STATUS, },
    { "Executing Cluster Transition",
      PCMK_XE_TRANSITION, },
    { "Failed Resource Actions",
      PCMK_XE_FAILURES, },
    { "Fencing History",
      PCMK_XE_FENCE_HISTORY, },
    { "Full List of Resources",
      PCMK_XE_RESOURCES, },
    { "Inactive Resources",
      PCMK_XE_RESOURCES, },
    { "Migration Summary",
      PCMK_XE_NODE_HISTORY, },
    { "Negative Location Constraints",
      PCMK_XE_BANS, },
    { "Node Attributes",
      PCMK_XE_NODE_ATTRIBUTES, },
    { "Operations",
      PCMK_XE_NODE_HISTORY, },
    { "Resource Config",
      PCMK_XE_RESOURCE_CONFIG, },
    { "Resource Operations",
      PCMK_XE_OPERATIONS, },
    { "Revised Cluster Status",
      PCMK_XE_REVISED_CLUSTER_STATUS, },
    { "Timings",
      PCMK_XE_TIMINGS, },
    { "Transition Summary",
      PCMK_XE_ACTIONS, },
    { "Utilization Information",
      PCMK_XE_UTILIZATIONS, },

    { NULL, NULL }
};

/* The first several elements of this struct must be the same as the first
 * several elements of private_data_s in lib/common/output_html.c.  That
 * struct gets passed to a bunch of the pcmk__output_xml_* functions which
 * assume an XML private_data_s.  Keeping them laid out the same means this
 * still works.
 */
typedef struct private_data_s {
    /* Begin members that must match the HTML version */
    xmlNode *root;
    GQueue *parent_q;
    GSList *errors;
    /* End members that must match the HTML version */
    bool legacy_xml;
    bool list_element;
} private_data_t;

static bool
has_root_node(pcmk__output_t *out)
{
    private_data_t *priv = NULL;

    pcmk__assert(out != NULL);

    priv = out->priv;
    return priv != NULL && priv->root != NULL;
}

static void
add_root_node(pcmk__output_t *out)
{
    private_data_t *priv = NULL;

    /* has_root_node will assert if out is NULL, so no need to do it here */
    if (has_root_node(out)) {
        return;
    }

    priv = out->priv;

    if (priv->legacy_xml) {
        priv->root = pcmk__xe_create(NULL, PCMK_XE_CRM_MON);
        pcmk__xe_set(priv->root, PCMK_XA_VERSION, PACEMAKER_VERSION);
    } else {
        priv->root = pcmk__xe_create(NULL, PCMK_XE_PACEMAKER_RESULT);
        pcmk__xe_set(priv->root, PCMK_XA_API_VERSION, PCMK__API_VERSION);
        pcmk__xe_set(priv->root, PCMK_XA_REQUEST,
                    pcmk__s(out->request, "libpacemaker"));
    }

    priv->parent_q = g_queue_new();
    g_queue_push_tail(priv->parent_q, priv->root);
}

static void
xml_free_priv(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    if (out == NULL || out->priv == NULL) {
        return;
    }

    priv = out->priv;

    if (has_root_node(out)) {
        pcmk__xml_free(priv->root);
        /* The elements of parent_q are xmlNodes that are a part of the
         * priv->root document, so the above line already frees them.  Don't
         * call g_queue_free_full here.
         */
        g_queue_free(priv->parent_q);
    }

    g_slist_free_full(priv->errors, free);
    free(priv);
    out->priv = NULL;
}

static bool
xml_init(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    pcmk__assert(out != NULL);

    /* If xml_init was previously called on this output struct, just return. */
    if (out->priv != NULL) {
        return true;
    } else {
        out->priv = calloc(1, sizeof(private_data_t));
        if (out->priv == NULL) {
            return false;
        }

        priv = out->priv;
    }

    priv->errors = NULL;

    return true;
}

static void
add_error_node(gpointer data, gpointer user_data) {
    const char *str = (const char *) data;
    xmlNodePtr node = (xmlNodePtr) user_data;

    node = pcmk__xe_create(node, PCMK_XE_ERROR);
    pcmk__xe_set_content(node, "%s", str);
}

static void
xml_finish(pcmk__output_t *out, crm_exit_t exit_status, bool print, void **copy_dest) {
    private_data_t *priv = NULL;
    xmlNodePtr node;

    pcmk__assert(out != NULL);
    priv = out->priv;

    if (priv == NULL) {
        return;
    }

    add_root_node(out);

    if (priv->legacy_xml) {
        GSList *node = priv->errors;

        if (exit_status != CRM_EX_OK) {
            fprintf(stderr, "%s\n", crm_exit_str(exit_status));
        }

        while (node != NULL) {
            fprintf(stderr, "%s\n", (char *) node->data);
            node = node->next;
        }
    } else {
        node = pcmk__xe_create(priv->root, PCMK_XE_STATUS);
        pcmk__xe_set_int(node, PCMK_XA_CODE, exit_status);
        pcmk__xe_set(node, PCMK_XA_MESSAGE, crm_exit_str(exit_status));

        if (g_slist_length(priv->errors) > 0) {
            xmlNodePtr errors_node = pcmk__xe_create(node, PCMK_XE_ERRORS);
            g_slist_foreach(priv->errors, add_error_node, (gpointer) errors_node);
        }
    }

    if (print) {
        pcmk__xml2fd(fileno(out->dest), priv->root);
    }

    if (copy_dest != NULL) {
        *copy_dest = pcmk__xml_copy(NULL, priv->root);
    }
}

static void
xml_reset(pcmk__output_t *out) {
    pcmk__assert(out != NULL);

    out->dest = freopen(NULL, "w", out->dest);
    pcmk__assert(out->dest != NULL);

    xml_free_priv(out);
    xml_init(out);
}

static void
xml_subprocess_output(pcmk__output_t *out, int exit_status,
                      const char *proc_stdout, const char *proc_stderr) {
    xmlNodePtr node, child_node;

    pcmk__assert(out != NULL);

    node = pcmk__output_xml_create_parent(out, PCMK_XE_COMMAND);
    pcmk__xe_set_int(node, PCMK_XA_CODE, exit_status);

    if (proc_stdout != NULL) {
        child_node = pcmk__xe_create(node, PCMK_XE_OUTPUT);
        pcmk__xe_set_content(child_node, "%s", proc_stdout);
        pcmk__xe_set(child_node, PCMK_XA_SOURCE, "stdout");
    }

    if (proc_stderr != NULL) {
        child_node = pcmk__xe_create(node, PCMK_XE_OUTPUT);
        pcmk__xe_set_content(child_node, "%s", proc_stderr);
        pcmk__xe_set(child_node, PCMK_XA_SOURCE, "stderr");
    }
}

static void
xml_version(pcmk__output_t *out)
{
    const char *author = "Andrew Beekhof and the Pacemaker project "
                         "contributors";
    pcmk__assert(out != NULL);

    pcmk__output_create_xml_node(out, PCMK_XE_VERSION,
                                 PCMK_XA_PROGRAM, "Pacemaker",
                                 PCMK_XA_VERSION, PACEMAKER_VERSION,
                                 PCMK_XA_AUTHOR, author,
                                 PCMK_XA_BUILD, BUILD_VERSION,
                                 PCMK_XA_FEATURES, CRM_FEATURES,
                                 NULL);
}

G_GNUC_PRINTF(2, 3)
static void
xml_err(pcmk__output_t *out, const char *format, ...) {
    private_data_t *priv = NULL;
    int len = 0;
    char *buf = NULL;
    va_list ap;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    add_root_node(out);

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    pcmk__assert(len > 0);
    va_end(ap);

    priv->errors = g_slist_append(priv->errors, buf);
}

G_GNUC_PRINTF(2, 3)
static int
xml_info(pcmk__output_t *out, const char *format, ...) {
    return pcmk_rc_no_output;
}

static void
xml_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    xmlNodePtr parent = NULL;
    xmlNodePtr cdata_node = NULL;

    pcmk__assert(out != NULL);

    parent = pcmk__output_create_xml_node(out, name, NULL);
    if (parent == NULL) {
        return;
    }
    cdata_node = xmlNewCDataBlock(parent->doc, (const xmlChar *) buf,
                                  strlen(buf));
    xmlAddChild(parent, cdata_node);
}

G_GNUC_PRINTF(4, 5)
static void
xml_begin_list(pcmk__output_t *out, const char *singular_noun, const char *plural_noun,
               const char *format, ...) {
    va_list ap;
    char *name = NULL;
    char *buf = NULL;
    int len;
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    pcmk__assert(len >= 0);
    va_end(ap);

    for (const subst_t *s = substitutions; s->from != NULL; s++) {
        if (strcmp(s->from, buf) == 0) {
            name = g_strdup(s->to);
            break;
        }
    }

    if (name == NULL) {
        name = g_ascii_strdown(buf, -1);
    }

    if (priv->list_element) {
        xmlNode *xml = pcmk__output_xml_create_parent(out, PCMK_XE_LIST);

        pcmk__xe_set(xml, PCMK_XA_NAME, name);

    } else {
        pcmk__output_xml_create_parent(out, name);
    }

    g_free(name);
    free(buf);
}

G_GNUC_PRINTF(3, 4)
static void
xml_list_item(pcmk__output_t *out, const char *name, const char *format, ...) {
    xmlNodePtr item_node = NULL;
    va_list ap;
    char *buf = NULL;
    int len;

    pcmk__assert(out != NULL);

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    pcmk__assert(len >= 0);
    va_end(ap);

    item_node = pcmk__output_create_xml_text_node(out, PCMK_XE_ITEM, buf);

    if (name != NULL) {
        pcmk__xe_set(item_node, PCMK_XA_NAME, name);
    }

    free(buf);
}

static void
xml_increment_list(pcmk__output_t *out) {
    /* This function intentially left blank */
}

static void
xml_end_list(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    if (priv->list_element) {
        char *buf = NULL;
        xmlNodePtr node;

        /* Do not free node here - it's still part of the document */
        node = g_queue_pop_tail(priv->parent_q);
        buf = pcmk__assert_asprintf("%lu", xmlChildElementCount(node));
        pcmk__xe_set(node, PCMK_XA_COUNT, buf);
        free(buf);
    } else {
        /* Do not free this result - it's still part of the document */
        g_queue_pop_tail(priv->parent_q);
    }
}

static bool
xml_is_quiet(pcmk__output_t *out) {
    return false;
}

static void
xml_spacer(pcmk__output_t *out) {
    /* This function intentionally left blank */
}

static void
xml_progress(pcmk__output_t *out, bool end) {
    /* This function intentionally left blank */
}

pcmk__output_t *
pcmk__mk_xml_output(char **argv) {
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->fmt_name = "xml";
    retval->request = pcmk__quote_cmdline(argv);

    retval->init = xml_init;
    retval->free_priv = xml_free_priv;
    retval->finish = xml_finish;
    retval->reset = xml_reset;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->subprocess_output = xml_subprocess_output;
    retval->version = xml_version;
    retval->info = xml_info;
    retval->transient = xml_info;
    retval->err = xml_err;
    retval->output_xml = xml_output_xml;

    retval->begin_list = xml_begin_list;
    retval->list_item = xml_list_item;
    retval->increment_list = xml_increment_list;
    retval->end_list = xml_end_list;

    retval->is_quiet = xml_is_quiet;
    retval->spacer = xml_spacer;
    retval->progress = xml_progress;
    retval->prompt = pcmk__text_prompt;

    return retval;
}

xmlNode *
pcmk__output_xml_create_parent(pcmk__output_t *out, const char *name)
{
    xmlNodePtr node = NULL;

    pcmk__assert(out != NULL);
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return NULL);

    node = pcmk__output_create_xml_node(out, name, NULL);

    pcmk__output_xml_push_parent(out, node);
    return node;
}

void
pcmk__output_xml_add_node_copy(pcmk__output_t *out, xmlNodePtr node) {
    private_data_t *priv = NULL;
    xmlNodePtr parent = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL) && (node != NULL));
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return);

    add_root_node(out);

    priv = out->priv;
    parent = g_queue_peek_tail(priv->parent_q);

    // Shouldn't happen unless the caller popped priv->root
    CRM_CHECK(parent != NULL, return);

    pcmk__xml_copy(parent, node);
}

xmlNodePtr
pcmk__output_create_xml_node(pcmk__output_t *out, const char *name, ...) {
    xmlNodePtr node = NULL;
    private_data_t *priv = NULL;
    va_list args;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return NULL);

    add_root_node(out);

    priv = out->priv;

    node = pcmk__xe_create(g_queue_peek_tail(priv->parent_q), name);
    va_start(args, name);
    pcmk__xe_set_propv(node, args);
    va_end(args);

    return node;
}

xmlNodePtr
pcmk__output_create_xml_text_node(pcmk__output_t *out, const char *name, const char *content) {
    xmlNodePtr node = NULL;

    pcmk__assert(out != NULL);
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return NULL);

    node = pcmk__output_create_xml_node(out, name, NULL);
    pcmk__xe_set_content(node, "%s", content);
    return node;
}

void
pcmk__output_xml_push_parent(pcmk__output_t *out, xmlNodePtr parent) {
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL) && (parent != NULL));
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return);

    add_root_node(out);

    priv = out->priv;

    g_queue_push_tail(priv->parent_q, parent);
}

void
pcmk__output_xml_pop_parent(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return);

    add_root_node(out);

    priv = out->priv;

    pcmk__assert(g_queue_get_length(priv->parent_q) > 0);
    /* Do not free this result - it's still part of the document */
    g_queue_pop_tail(priv->parent_q);
}

xmlNodePtr
pcmk__output_xml_peek_parent(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return NULL);

    add_root_node(out);

    priv = out->priv;

    /* If queue is empty NULL will be returned */
    return g_queue_peek_tail(priv->parent_q);
}

bool
pcmk__output_get_legacy_xml(pcmk__output_t *out)
{
    private_data_t *priv = NULL;

    pcmk__assert(out != NULL);

    if (!pcmk__str_eq(out->fmt_name, "xml", pcmk__str_none)) {
        return false;
    }

    pcmk__assert(out->priv != NULL);

    priv = out->priv;
    return priv->legacy_xml;
}

void
pcmk__output_set_legacy_xml(pcmk__output_t *out)
{
    private_data_t *priv = NULL;

    pcmk__assert(out != NULL);

    if (!pcmk__str_eq(out->fmt_name, "xml", pcmk__str_none)) {
        return;
    }

    pcmk__assert(out->priv != NULL);

    priv = out->priv;
    priv->legacy_xml = true;
}

void
pcmk__output_enable_list_element(pcmk__output_t *out)
{
    private_data_t *priv = NULL;

    pcmk__assert(out != NULL);

    if (!pcmk__str_eq(out->fmt_name, "xml", pcmk__str_none)) {
        return;
    }

    pcmk__assert(out->priv != NULL);

    priv = out->priv;
    priv->list_element = true;
}
