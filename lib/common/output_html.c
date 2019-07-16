/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <ctype.h>
#include <libxml/HTMLtree.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <crm/crm.h>
#include <crm/common/output.h>
#include <crm/common/xml.h>

static const char *stylesheet_default =
    ".bold { font-weight: bold }\n"
    ".warning { color: red, font-weight: bold }";

static gboolean cgi_output = FALSE;
static int meta_refresh = 0;
static char *stylesheet_link = NULL;
static char *title = NULL;

GOptionEntry pcmk__html_output_entries[] = {
    { "cgi-output", 0, 0, G_OPTION_ARG_NONE, &cgi_output,
      "Add text needed to use output in a CGI program",
      NULL },

    { "meta-refresh", 0, 0, G_OPTION_ARG_INT, &meta_refresh,
      "How often to refresh",
      "SECONDS" },

    { "stylesheet-link", 0, 0, G_OPTION_ARG_STRING, &stylesheet_link,
      "Link to an external CSS stylesheet",
      "URI" },

    { "title", 0, 0, G_OPTION_ARG_STRING, &title,
      "Page title (defaults to command line)",
      "TITLE" },

    { NULL }
};

typedef struct private_data_s {
    xmlNode *root;
    GQueue *parent_q;
    GSList *errors;
} private_data_t;

static void
html_free_priv(pcmk__output_t *out) {
    private_data_t *priv = out->priv;

    if (priv == NULL) {
        return;
    }

    xmlFreeNode(priv->root);
    g_queue_free(priv->parent_q);
    g_slist_free(priv->errors);
    free(priv);
}

static bool
html_init(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    /* If html_init was previously called on this output struct, just return. */
    if (out->priv != NULL) {
        return true;
    } else {
        out->priv = calloc(1, sizeof(private_data_t));
        if (out->priv == NULL) {
            return false;
        }

        priv = out->priv;
    }

    priv->parent_q = g_queue_new();

    priv->root = create_xml_node(NULL, "html");
    xmlCreateIntSubset(priv->root->doc, (pcmkXmlStr) "html", NULL, NULL);

    xmlSetProp(priv->root, (pcmkXmlStr) "lang", (pcmkXmlStr) "en");
    g_queue_push_tail(priv->parent_q, priv->root);
    priv->errors = NULL;

    pcmk__output_xml_create_parent(out, "body");

    return true;
}

static void
add_error_node(gpointer data, gpointer user_data) {
    char *str = (char *) data;
    pcmk__output_t *out = (pcmk__output_t *) user_data;
    out->list_item(out, NULL, str);
}

static void
html_finish(pcmk__output_t *out, crm_exit_t exit_status) {
    private_data_t *priv = out->priv;
    htmlNodePtr head_node = NULL;
    htmlNodePtr charset_node = NULL;

    /* If root is NULL, html_init failed and we are being called from pcmk__output_free
     * in the pcmk__output_new path.
     */
    if (priv->root == NULL) {
        return;
    }

    if (cgi_output) {
        fprintf(out->dest, "Content-Type: text/html\n\n");
    }

    /* Add the head node last - it's not needed earlier because it doesn't contain
     * anything else that the user could add, and we want it done last to pick up
     * any options that may have been given.
     */
    head_node = xmlNewNode(NULL, (pcmkXmlStr) "head");

    if (title != NULL ) {
        pcmk_create_xml_text_node(head_node, "title", title);
    } else if (out->request != NULL) {
        pcmk_create_xml_text_node(head_node, "title", out->request);
    }

    charset_node = create_xml_node(head_node, "meta");
    xmlSetProp(charset_node, (pcmkXmlStr) "charset", (pcmkXmlStr) "utf-8");

    if (meta_refresh != 0) {
        htmlNodePtr refresh_node = create_xml_node(head_node, "meta");
        xmlSetProp(refresh_node, (pcmkXmlStr) "http-equiv", (pcmkXmlStr) "refresh");
        xmlSetProp(refresh_node, (pcmkXmlStr) "content", (pcmkXmlStr) crm_itoa(meta_refresh));
    }

    /* Stylesheets are included two different ways.  The first is via a built-in
     * default (see the stylesheet_default const above).  The second is via the
     * "stylesheet-link" option, and this should obviously be a link to a
     * stylesheet.  The second can override the first.  At least one should be
     * given.
     */
    pcmk_create_xml_text_node(head_node, "style", stylesheet_default);

    if (stylesheet_link != NULL) {
        htmlNodePtr link_node = create_xml_node(head_node, "link");
        xmlSetProp(link_node, (pcmkXmlStr) "rel", (pcmkXmlStr) "stylesheet");
        xmlSetProp(link_node, (pcmkXmlStr) "href", (pcmkXmlStr) stylesheet_link);
    }

    xmlAddPrevSibling(priv->root->children, head_node);

    if (g_slist_length(priv->errors) > 0) {
        out->begin_list(out, "Errors", NULL, NULL);
        g_slist_foreach(priv->errors, add_error_node, (gpointer) out);
        out->end_list(out);
    }

    htmlDocDump(out->dest, priv->root->doc);
}

static void
html_reset(pcmk__output_t *out) {
    private_data_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

    htmlDocDump(out->dest, priv->root->doc);

    html_free_priv(out);
    html_init(out);
}

static void
html_subprocess_output(pcmk__output_t *out, int exit_status,
                      const char *proc_stdout, const char *proc_stderr) {
    char *rc_buf = NULL;
    private_data_t *priv = out->priv;
    CRM_ASSERT(priv != NULL);

    rc_buf = crm_strdup_printf("Return code: %d", exit_status);

    pcmk_create_xml_text_node(g_queue_peek_tail(priv->parent_q), "h2", "Command Output");
    pcmk__output_create_html_node(out, "div", NULL, NULL, rc_buf);

    if (proc_stdout != NULL) {
        pcmk__output_create_html_node(out, "div", NULL, NULL, "Stdout");
        pcmk__output_create_html_node(out, "div", NULL, "output", proc_stdout);
    }
    if (proc_stderr != NULL) {
        pcmk__output_create_html_node(out, "div", NULL, NULL, "Stderr");
        pcmk__output_create_html_node(out, "div", NULL, "output", proc_stderr);
    }

    free(rc_buf);
}

static void
html_version(pcmk__output_t *out, bool extended) {
    private_data_t *priv = out->priv;
    CRM_ASSERT(priv != NULL);

    pcmk_create_xml_text_node(g_queue_peek_tail(priv->parent_q), "h2", "Version Information");
    pcmk__output_create_html_node(out, "div", NULL, NULL, "Program: Pacemaker");
    pcmk__output_create_html_node(out, "div", NULL, NULL, crm_strdup_printf("Version: %s", PACEMAKER_VERSION));
    pcmk__output_create_html_node(out, "div", NULL, NULL, "Author: Andrew Beekhof");
    pcmk__output_create_html_node(out, "div", NULL, NULL, crm_strdup_printf("Build: %s", BUILD_VERSION));
    pcmk__output_create_html_node(out, "div", NULL, NULL, crm_strdup_printf("Features: %s", CRM_FEATURES));
}

G_GNUC_PRINTF(2, 3)
static void
html_err(pcmk__output_t *out, const char *format, ...) {
    private_data_t *priv = out->priv;
    int len = 0;
    char *buf = NULL;
    va_list ap;

    CRM_ASSERT(priv != NULL);
    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    CRM_ASSERT(len > 0);
    va_end(ap);

    priv->errors = g_slist_append(priv->errors, buf);
}

G_GNUC_PRINTF(2, 3)
static void
html_info(pcmk__output_t *out, const char *format, ...) {
    /* This function intentially left blank */
}

static void
html_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    htmlNodePtr node = NULL;
    private_data_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

    node = pcmk__output_create_html_node(out, "pre", NULL, NULL, buf);
    xmlSetProp(node, (pcmkXmlStr) "lang", (pcmkXmlStr) "xml");
}

static void
html_begin_list(pcmk__output_t *out, const char *name,
               const char *singular_noun, const char *plural_noun) {
    private_data_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

    if (name != NULL) {
        pcmk_create_xml_text_node(g_queue_peek_tail(priv->parent_q), "h2", name);
    }

    pcmk__output_xml_create_parent(out, "ul");
}

static void
html_list_item(pcmk__output_t *out, const char *name, const char *content) {
    private_data_t *priv = out->priv;
    htmlNodePtr item_node = NULL;

    CRM_ASSERT(priv != NULL);

    item_node = pcmk_create_xml_text_node(g_queue_peek_tail(priv->parent_q), "li", content);

    if (name != NULL) {
        xmlSetProp(item_node, (pcmkXmlStr) "class", (pcmkXmlStr) name);
    }
}

static void
html_end_list(pcmk__output_t *out) {
    private_data_t *priv = out->priv;

    CRM_ASSERT(priv != NULL);

    g_queue_pop_tail(priv->parent_q);
}

pcmk__output_t *
pcmk__mk_html_output(char **argv) {
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->fmt_name = "html";
    retval->request = g_strjoinv(" ", argv);
    retval->supports_quiet = false;

    retval->init = html_init;
    retval->free_priv = html_free_priv;
    retval->finish = html_finish;
    retval->reset = html_reset;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->subprocess_output = html_subprocess_output;
    retval->version = html_version;
    retval->info = html_info;
    retval->err = html_err;
    retval->output_xml = html_output_xml;

    retval->begin_list = html_begin_list;
    retval->list_item = html_list_item;
    retval->end_list = html_end_list;

    return retval;
}

xmlNodePtr
pcmk__output_create_html_node(pcmk__output_t *out, const char *element_name, const char *id,
                       const char *class_name, const char *text) {
    htmlNodePtr node = xmlNewNode(NULL, (pcmkXmlStr) element_name);

    xmlNodeSetContent(node, (pcmkXmlStr) text);

    if (class_name != NULL) {
        xmlSetProp(node, (pcmkXmlStr) "class", (pcmkXmlStr) class_name);
    }

    if (id != NULL) {
        xmlSetProp(node, (pcmkXmlStr) "id", (pcmkXmlStr) id);
    }

    pcmk__output_xml_add_node(out, node);
    return node;
}
