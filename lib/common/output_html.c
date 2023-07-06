/*
 * Copyright 2019-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <ctype.h>
#include <libxml/HTMLtree.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include <crm/common/cmdline_internal.h>
#include <crm/common/xml.h>

static const char *stylesheet_default =
    ".bold { font-weight: bold }\n"

    ".online { color: green }\n"
    ".offline { color: red }\n"
    ".maint { color: blue }\n"
    ".standby { color: blue }\n"
    ".health_red { color: red }\n"
    ".health_yellow { color: GoldenRod }\n"

    ".rsc-failed { color: red }\n"
    ".rsc-failure-ignored { color: DarkGreen }\n"
    ".rsc-managed { color: blue }\n"
    ".rsc-multiple { color: orange }\n"
    ".rsc-ok { color: green }\n"

    ".warning { color: red; font-weight: bold }";

static gboolean cgi_output = FALSE;
static char *stylesheet_link = NULL;
static char *title = NULL;
static GSList *extra_headers = NULL;

GOptionEntry pcmk__html_output_entries[] = {
    { "html-cgi", 0, 0, G_OPTION_ARG_NONE, &cgi_output,
      "Add CGI headers (requires --output-as=html)",
      NULL },

    { "html-stylesheet", 0, 0, G_OPTION_ARG_STRING, &stylesheet_link,
      "Link to an external stylesheet (requires --output-as=html)",
      "URI" },

    { "html-title", 0, 0, G_OPTION_ARG_STRING, &title,
      "Specify a page title (requires --output-as=html)",
      "TITLE" },

    { NULL }
};

/* The first several elements of this struct must be the same as the first
 * several elements of private_data_s in lib/common/output_xml.c.  This
 * struct gets passed to a bunch of the pcmk__output_xml_* functions which
 * assume an XML private_data_s.  Keeping them laid out the same means this
 * still works.
 */
typedef struct private_data_s {
    /* Begin members that must match the XML version */
    xmlNode *root;
    GQueue *parent_q;
    GSList *errors;
    /* End members that must match the XML version */
} private_data_t;

static void
html_free_priv(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    if (out == NULL || out->priv == NULL) {
        return;
    }

    priv = out->priv;

    xmlFreeNode(priv->root);
    g_queue_free(priv->parent_q);
    g_slist_free(priv->errors);
    free(priv);
    out->priv = NULL;
}

static bool
html_init(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL);

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

    crm_xml_add(priv->root, "lang", "en");
    g_queue_push_tail(priv->parent_q, priv->root);
    priv->errors = NULL;

    pcmk__output_xml_create_parent(out, "body", NULL);

    return true;
}

static void
add_error_node(gpointer data, gpointer user_data) {
    char *str = (char *) data;
    pcmk__output_t *out = (pcmk__output_t *) user_data;
    out->list_item(out, NULL, "%s", str);
}

static void
html_finish(pcmk__output_t *out, crm_exit_t exit_status, bool print, void **copy_dest) {
    private_data_t *priv = NULL;
    htmlNodePtr head_node = NULL;
    htmlNodePtr charset_node = NULL;

    CRM_ASSERT(out != NULL);

    priv = out->priv;

    /* If root is NULL, html_init failed and we are being called from pcmk__output_free
     * in the pcmk__output_new path.
     */
    if (priv == NULL || priv->root == NULL) {
        return;
    }

    if (cgi_output && print) {
        fprintf(out->dest, "Content-Type: text/html\n\n");
    }

    /* Add the head node last - it's not needed earlier because it doesn't contain
     * anything else that the user could add, and we want it done last to pick up
     * any options that may have been given.
     */
    head_node = xmlNewDocRawNode(NULL, NULL, (pcmkXmlStr) "head", NULL);

    if (title != NULL ) {
        pcmk_create_xml_text_node(head_node, "title", title);
    } else if (out->request != NULL) {
        pcmk_create_xml_text_node(head_node, "title", out->request);
    }

    charset_node = create_xml_node(head_node, "meta");
    crm_xml_add(charset_node, "charset", "utf-8");

    /* Add any extra header nodes the caller might have created. */
    for (int i = 0; i < g_slist_length(extra_headers); i++) {
        xmlAddChild(head_node, xmlCopyNode(g_slist_nth_data(extra_headers, i), 1));
    }

    /* Stylesheets are included two different ways.  The first is via a built-in
     * default (see the stylesheet_default const above).  The second is via the
     * html-stylesheet option, and this should obviously be a link to a
     * stylesheet.  The second can override the first.  At least one should be
     * given.
     */
    pcmk_create_xml_text_node(head_node, "style", stylesheet_default);

    if (stylesheet_link != NULL) {
        htmlNodePtr link_node = create_xml_node(head_node, "link");
        pcmk__xe_set_props(link_node, "rel", "stylesheet",
                           "href", stylesheet_link,
                           NULL);
    }

    xmlAddPrevSibling(priv->root->children, head_node);

    if (g_slist_length(priv->errors) > 0) {
        out->begin_list(out, "Errors", NULL, NULL);
        g_slist_foreach(priv->errors, add_error_node, (gpointer) out);
        out->end_list(out);
    }

    if (print) {
        htmlDocDump(out->dest, priv->root->doc);
    }

    if (copy_dest != NULL) {
        *copy_dest = copy_xml(priv->root);
    }

    g_slist_free_full(extra_headers, (GDestroyNotify) xmlFreeNode);
    extra_headers = NULL;
}

static void
html_reset(pcmk__output_t *out) {
    CRM_ASSERT(out != NULL);

    out->dest = freopen(NULL, "w", out->dest);
    CRM_ASSERT(out->dest != NULL);

    html_free_priv(out);
    html_init(out);
}

static void
html_subprocess_output(pcmk__output_t *out, int exit_status,
                       const char *proc_stdout, const char *proc_stderr) {
    char *rc_buf = NULL;

    CRM_ASSERT(out != NULL);

    rc_buf = crm_strdup_printf("Return code: %d", exit_status);

    pcmk__output_create_xml_text_node(out, "h2", "Command Output");
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
    CRM_ASSERT(out != NULL);

    pcmk__output_create_xml_text_node(out, "h2", "Version Information");
    pcmk__output_create_html_node(out, "div", NULL, NULL, "Program: Pacemaker");
    pcmk__output_create_html_node(out, "div", NULL, NULL, crm_strdup_printf("Version: %s", PACEMAKER_VERSION));
    pcmk__output_create_html_node(out, "div", NULL, NULL,
                                  "Author: Andrew Beekhof and "
                                  "the Pacemaker project contributors");
    pcmk__output_create_html_node(out, "div", NULL, NULL, crm_strdup_printf("Build: %s", BUILD_VERSION));
    pcmk__output_create_html_node(out, "div", NULL, NULL, crm_strdup_printf("Features: %s", CRM_FEATURES));
}

G_GNUC_PRINTF(2, 3)
static void
html_err(pcmk__output_t *out, const char *format, ...) {
    private_data_t *priv = NULL;
    int len = 0;
    char *buf = NULL;
    va_list ap;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    priv->errors = g_slist_append(priv->errors, buf);
}

G_GNUC_PRINTF(2, 3)
static int
html_info(pcmk__output_t *out, const char *format, ...) {
    return pcmk_rc_no_output;
}

static void
html_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    htmlNodePtr node = NULL;

    CRM_ASSERT(out != NULL);

    node = pcmk__output_create_html_node(out, "pre", NULL, NULL, buf);
    crm_xml_add(node, "lang", "xml");
}

G_GNUC_PRINTF(4, 5)
static void
html_begin_list(pcmk__output_t *out, const char *singular_noun,
                const char *plural_noun, const char *format, ...) {
    int q_len = 0;
    private_data_t *priv = NULL;
    xmlNodePtr node = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    /* If we are already in a list (the queue depth is always at least
     * one because of the <html> element), first create a <li> element
     * to hold the <h2> and the new list.
     */
    q_len = g_queue_get_length(priv->parent_q);
    if (q_len > 2) {
        pcmk__output_xml_create_parent(out, "li", NULL);
    }

    if (format != NULL) {
        va_list ap;
        char *buf = NULL;
        int len;

        va_start(ap, format);
        len = vasprintf(&buf, format, ap);
        va_end(ap);
        CRM_ASSERT(len >= 0);

        if (q_len > 2) {
            pcmk__output_create_xml_text_node(out, "h3", buf);
        } else {
            pcmk__output_create_xml_text_node(out, "h2", buf);
        }

        free(buf);
    }

    node = pcmk__output_xml_create_parent(out, "ul", NULL);
    g_queue_push_tail(priv->parent_q, node);
}

G_GNUC_PRINTF(3, 4)
static void
html_list_item(pcmk__output_t *out, const char *name, const char *format, ...) {
    htmlNodePtr item_node = NULL;
    va_list ap;
    char *buf = NULL;
    int len;

    CRM_ASSERT(out != NULL);

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    item_node = pcmk__output_create_xml_text_node(out, "li", buf);
    free(buf);

    if (name != NULL) {
        crm_xml_add(item_node, "class", name);
    }
}

static void
html_increment_list(pcmk__output_t *out) {
    /* This function intentially left blank */
}

static void
html_end_list(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    CRM_ASSERT(out != NULL && out->priv != NULL);
    priv = out->priv;

    /* Remove the <ul> tag. */
    g_queue_pop_tail(priv->parent_q);
    pcmk__output_xml_pop_parent(out);

    /* Remove the <li> created for nested lists. */
    if (g_queue_get_length(priv->parent_q) > 2) {
        pcmk__output_xml_pop_parent(out);
    }
}

static bool
html_is_quiet(pcmk__output_t *out) {
    return false;
}

static void
html_spacer(pcmk__output_t *out) {
    CRM_ASSERT(out != NULL);
    pcmk__output_create_xml_node(out, "br", NULL);
}

static void
html_progress(pcmk__output_t *out, bool end) {
    /* This function intentially left blank */
}

pcmk__output_t *
pcmk__mk_html_output(char **argv) {
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->fmt_name = "html";
    retval->request = pcmk__quote_cmdline(argv);

    retval->init = html_init;
    retval->free_priv = html_free_priv;
    retval->finish = html_finish;
    retval->reset = html_reset;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->subprocess_output = html_subprocess_output;
    retval->version = html_version;
    retval->info = html_info;
    retval->transient = html_info;
    retval->err = html_err;
    retval->output_xml = html_output_xml;

    retval->begin_list = html_begin_list;
    retval->list_item = html_list_item;
    retval->increment_list = html_increment_list;
    retval->end_list = html_end_list;

    retval->is_quiet = html_is_quiet;
    retval->spacer = html_spacer;
    retval->progress = html_progress;
    retval->prompt = pcmk__text_prompt;

    return retval;
}

xmlNodePtr
pcmk__output_create_html_node(pcmk__output_t *out, const char *element_name, const char *id,
                              const char *class_name, const char *text) {
    htmlNodePtr node = NULL;

    CRM_ASSERT(out != NULL);
    CRM_CHECK(pcmk__str_eq(out->fmt_name, "html", pcmk__str_none), return NULL);

    node = pcmk__output_create_xml_text_node(out, element_name, text);

    if (class_name != NULL) {
        crm_xml_add(node, "class", class_name);
    }

    if (id != NULL) {
        crm_xml_add(node, "id", id);
    }

    return node;
}

void
pcmk__html_add_header(const char *name, ...) {
    htmlNodePtr header_node;
    va_list ap;

    va_start(ap, name);

    header_node = xmlNewDocRawNode(NULL, NULL, (pcmkXmlStr) name, NULL);
    while (1) {
        char *key = va_arg(ap, char *);
        char *value;

        if (key == NULL) {
            break;
        }

        value = va_arg(ap, char *);
        crm_xml_add(header_node, key, value);
    }

    extra_headers = g_slist_append(extra_headers, header_node);

    va_end(ap);
}
