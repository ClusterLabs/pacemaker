/*
 * Copyright 2019-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <crm/crm.h>
#include <crm/common/output.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>  /* pcmk__xml2fd */
#include <glib.h>

#include <crm/common/cmdline_internal.h>
#include <crm/common/xml.h>

static gboolean legacy_xml = FALSE;
static gboolean simple_list = FALSE;
static gboolean substitute = FALSE;

GOptionEntry pcmk__xml_output_entries[] = {
    { "xml-legacy", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &legacy_xml,
      NULL,
      NULL },
    { "xml-simple-list", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &simple_list,
      NULL,
      NULL },
    { "xml-substitute", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &substitute,
      NULL,
      NULL },

    { NULL }
};

typedef struct subst_s {
    const char *from;
    const char *to;
} subst_t;

static subst_t substitutions[] = {
    { "Active Resources",                               "resources" },
    { "Assignment Scores",                              "allocations" },
    { "Assignment Scores and Utilization Information",  "allocations_utilizations" },
    { "Cluster Summary",                                "summary" },
    { "Current cluster status",                         "cluster_status" },
    { "Executing Cluster Transition",                   "transition" },
    { "Failed Resource Actions",                        "failures" },
    { "Fencing History",                                "fence_history" },
    { "Full List of Resources",                         "resources" },
    { "Inactive Resources",                             "resources" },
    { "Migration Summary",                              "node_history" },
    { "Negative Location Constraints",                  "bans" },
    { "Node Attributes",                                "node_attributes" },
    { "Operations",                                     "node_history" },
    { "Resource Config",                                "resource_config" },
    { "Resource Operations",                            "operations" },
    { "Revised Cluster Status",                         "revised_cluster_status" },
    { "Transition Summary",                             "actions" },
    { "Utilization Information",                        "utilizations" },

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
} private_data_t;

static void
xml_free_priv(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    if (out == NULL || out->priv == NULL) {
        return;
    }

    priv = out->priv;

    free_xml(priv->root);
    g_queue_free(priv->parent_q);
    g_slist_free(priv->errors);
    free(priv);
    out->priv = NULL;
}

static bool
xml_init(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL);

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

    if (legacy_xml) {
        priv->root = create_xml_node(NULL, "crm_mon");
        crm_xml_add(priv->root, "version", PACEMAKER_VERSION);
    } else {
        priv->root = create_xml_node(NULL, "pacemaker-result");
        crm_xml_add(priv->root, "api-version", PCMK__API_VERSION);

        if (out->request != NULL) {
            crm_xml_add(priv->root, "request", out->request);
        }
    }

    priv->parent_q = g_queue_new();
    priv->errors = NULL;
    g_queue_push_tail(priv->parent_q, priv->root);

    /* Copy this from the file-level variable.  This means that it is only settable
     * as a command line option, and that pcmk__output_new must be called after all
     * command line processing is completed.
     */
    priv->legacy_xml = legacy_xml;

    return true;
}

static void
add_error_node(gpointer data, gpointer user_data) {
    char *str = (char *) data;
    xmlNodePtr node = (xmlNodePtr) user_data;
    pcmk_create_xml_text_node(node, "error", str);
}

static void
xml_finish(pcmk__output_t *out, crm_exit_t exit_status, bool print, void **copy_dest) {
    private_data_t *priv = NULL;
    xmlNodePtr node;

    CRM_ASSERT(out != NULL);
    priv = out->priv;

    /* If root is NULL, xml_init failed and we are being called from pcmk__output_free
     * in the pcmk__output_new path.
     */
    if (priv == NULL || priv->root == NULL) {
        return;
    }

    if (legacy_xml) {
        GSList *node = priv->errors;

        if (exit_status != CRM_EX_OK) {
            fprintf(stderr, "%s\n", crm_exit_str(exit_status));
        }

        while (node != NULL) {
            fprintf(stderr, "%s\n", (char *) node->data);
            node = node->next;
        }
    } else {
        char *rc_as_str = pcmk__itoa(exit_status);

        node = create_xml_node(priv->root, "status");
        pcmk__xe_set_props(node, "code", rc_as_str,
                           "message", crm_exit_str(exit_status),
                           NULL);

        if (g_slist_length(priv->errors) > 0) {
            xmlNodePtr errors_node = create_xml_node(node, "errors");
            g_slist_foreach(priv->errors, add_error_node, (gpointer) errors_node);
        }

        free(rc_as_str);
    }

    if (print) {
        pcmk__xml2fd(fileno(out->dest), priv->root);
    }

    if (copy_dest != NULL) {
        *copy_dest = copy_xml(priv->root);
    }
}

static void
xml_reset(pcmk__output_t *out) {
    CRM_ASSERT(out != NULL);

    out->dest = freopen(NULL, "w", out->dest);
    CRM_ASSERT(out->dest != NULL);

    xml_free_priv(out);
    xml_init(out);
}

static void
xml_subprocess_output(pcmk__output_t *out, int exit_status,
                      const char *proc_stdout, const char *proc_stderr) {
    xmlNodePtr node, child_node;
    char *rc_as_str = NULL;

    CRM_ASSERT(out != NULL);

    rc_as_str = pcmk__itoa(exit_status);

    node = pcmk__output_xml_create_parent(out, "command",
                                          "code", rc_as_str,
                                          NULL);

    if (proc_stdout != NULL) {
        child_node = pcmk_create_xml_text_node(node, "output", proc_stdout);
        crm_xml_add(child_node, "source", "stdout");
    }

    if (proc_stderr != NULL) {
        child_node = pcmk_create_xml_text_node(node, "output", proc_stderr);
        crm_xml_add(child_node, "source", "stderr");
    }

    free(rc_as_str);
}

static void
xml_version(pcmk__output_t *out, bool extended) {
    CRM_ASSERT(out != NULL);

    pcmk__output_create_xml_node(out, "version",
                                 "program", "Pacemaker",
                                 "version", PACEMAKER_VERSION,
                                 "author", "Andrew Beekhof and the "
                                           "Pacemaker project contributors",
                                 "build", BUILD_VERSION,
                                 "features", CRM_FEATURES,
                                 NULL);
}

G_GNUC_PRINTF(2, 3)
static void
xml_err(pcmk__output_t *out, const char *format, ...) {
    private_data_t *priv = NULL;
    int len = 0;
    char *buf = NULL;
    va_list ap;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    CRM_ASSERT(len > 0);
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

    CRM_ASSERT(out != NULL);

    parent = pcmk__output_create_xml_node(out, name, NULL);
    if (parent == NULL) {
        return;
    }
    cdata_node = xmlNewCDataBlock(parent->doc, (pcmkXmlStr) buf, strlen(buf));
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

    CRM_ASSERT(out != NULL);

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    if (substitute) {
        for (subst_t *s = substitutions; s->from != NULL; s++) {
            if (!strcmp(s->from, buf)) {
                name = g_strdup(s->to);
                break;
            }
        }
    }

    if (name == NULL) {
        name = g_ascii_strdown(buf, -1);
    }

    if (legacy_xml || simple_list) {
        pcmk__output_xml_create_parent(out, name, NULL);
    } else {
        pcmk__output_xml_create_parent(out, "list",
                                       "name", name,
                                       NULL);
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

    CRM_ASSERT(out != NULL);

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    item_node = pcmk__output_create_xml_text_node(out, "item", buf);

    if (name != NULL) {
        crm_xml_add(item_node, "name", name);
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

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    if (priv->legacy_xml || simple_list) {
        g_queue_pop_tail(priv->parent_q);
    } else {
        char *buf = NULL;
        xmlNodePtr node;

        node = g_queue_pop_tail(priv->parent_q);
        buf = crm_strdup_printf("%lu", xmlChildElementCount(node));
        crm_xml_add(node, "count", buf);
        free(buf);
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

xmlNodePtr
pcmk__output_xml_create_parent(pcmk__output_t *out, const char *name, ...) {
    va_list args;
    xmlNodePtr node = NULL;

    CRM_ASSERT(out != NULL);
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return NULL);

    node = pcmk__output_create_xml_node(out, name, NULL);

    va_start(args, name);
    pcmk__xe_set_propv(node, args);
    va_end(args);

    pcmk__output_xml_push_parent(out, node);
    return node;
}

void
pcmk__output_xml_add_node_copy(pcmk__output_t *out, xmlNodePtr node) {
    private_data_t *priv = NULL;
    xmlNodePtr parent = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    CRM_ASSERT(node != NULL);
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return);

    priv = out->priv;
    parent = g_queue_peek_tail(priv->parent_q);

    // Shouldn't happen unless the caller popped priv->root
    CRM_CHECK(parent != NULL, return);

    add_node_copy(parent, node);
}

xmlNodePtr
pcmk__output_create_xml_node(pcmk__output_t *out, const char *name, ...) {
    xmlNodePtr node = NULL;
    private_data_t *priv = NULL;
    va_list args;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return NULL);

    priv = out->priv;

    node = create_xml_node(g_queue_peek_tail(priv->parent_q), name);
    va_start(args, name);
    pcmk__xe_set_propv(node, args);
    va_end(args);

    return node;
}

xmlNodePtr
pcmk__output_create_xml_text_node(pcmk__output_t *out, const char *name, const char *content) {
    xmlNodePtr node = NULL;

    CRM_ASSERT(out != NULL);
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return NULL);

    node = pcmk__output_create_xml_node(out, name, NULL);
    xmlNodeSetContent(node, (pcmkXmlStr) content);
    return node;
}

void
pcmk__output_xml_push_parent(pcmk__output_t *out, xmlNodePtr parent) {
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    CRM_ASSERT(parent != NULL);
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return);

    priv = out->priv;

    g_queue_push_tail(priv->parent_q, parent);
}

void
pcmk__output_xml_pop_parent(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return);

    priv = out->priv;

    CRM_ASSERT(g_queue_get_length(priv->parent_q) > 0);
    g_queue_pop_tail(priv->parent_q);
}

xmlNodePtr
pcmk__output_xml_peek_parent(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    CRM_CHECK(pcmk__str_any_of(out->fmt_name, "xml", "html", NULL), return NULL);

    priv = out->priv;

    /* If queue is empty NULL will be returned */
    return g_queue_peek_tail(priv->parent_q);
}
