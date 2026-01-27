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

#include <libxml/HTMLtree.h>
#include <libxml/tree.h>                    // xmlNode
#include <libxml/xmlstring.h>               // xmlChar

#include <crm/common/xml.h>

static const char *stylesheet_default =
    "." PCMK__VALUE_BOLD " { font-weight: bold }\n"

    "." PCMK_VALUE_ONLINE " { color: green }\n"
    "." PCMK_VALUE_OFFLINE " { color: red }\n"
    "." PCMK__VALUE_MAINT " { color: blue }\n"
    "." PCMK_VALUE_STANDBY " { color: blue }\n"
    "." PCMK__VALUE_HEALTH_RED " { color: red }\n"
    "." PCMK__VALUE_HEALTH_YELLOW " { color: GoldenRod }\n"

    "." PCMK__VALUE_RSC_FAILED " { color: red }\n"
    "." PCMK__VALUE_RSC_FAILURE_IGNORED " { color: DarkGreen }\n"
    "." PCMK__VALUE_RSC_MANAGED " { color: blue }\n"
    "." PCMK__VALUE_RSC_MULTIPLE " { color: orange }\n"
    "." PCMK__VALUE_RSC_OK " { color: green }\n"

    "." PCMK__VALUE_WARNING " { color: red; font-weight: bold }";

/* @TODO stylesheet_link, title, and extra_headers should be set
 * per-output-object and should be freed before exit
 */
static gboolean cgi_output = FALSE;
static gchar *stylesheet_link = NULL;
static gchar *title = NULL;
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

    pcmk__xml_free(priv->root);
    /* The elements of parent_q are xmlNodes that are a part of the
     * priv->root document, so the above line already frees them.  Don't
     * call g_queue_free_full here.
     */
    g_queue_free(priv->parent_q);
    g_slist_free_full(priv->errors, free);
    free(priv);
    out->priv = NULL;
}

static bool
html_init(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    pcmk__assert(out != NULL);

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

    priv->root = pcmk__xe_create(NULL, "html");
    xmlCreateIntSubset(priv->root->doc, (const xmlChar *) "html", NULL, NULL);

    pcmk__xe_set(priv->root, PCMK_XA_LANG, PCMK__VALUE_EN);
    g_queue_push_tail(priv->parent_q, priv->root);
    priv->errors = NULL;

    pcmk__output_xml_create_parent(out, "body");

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
    xmlNode *child_node = NULL;

    pcmk__assert(out != NULL);

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
    head_node = pcmk__xe_create(priv->root, "head");
    xmlAddPrevSibling(priv->root->children, head_node);

    if (title != NULL ) {
        child_node = pcmk__xe_create(head_node, "title");
        pcmk__xe_set_content(child_node, "%s", title);
    } else if (out->request != NULL) {
        child_node = pcmk__xe_create(head_node, "title");
        pcmk__xe_set_content(child_node, "%s", out->request);
    }

    charset_node = pcmk__xe_create(head_node, PCMK__XE_META);
    pcmk__xe_set(charset_node, "charset", "utf-8");

    /* Add any extra header nodes the caller might have created. */
    for (GSList *iter = extra_headers; iter != NULL; iter = iter->next) {
        pcmk__xml_copy(head_node, (xmlNode *) iter->data);
    }

    /* Stylesheets are included two different ways.  The first is via a built-in
     * default (see the stylesheet_default const above).  The second is via the
     * html-stylesheet option, and this should obviously be a link to a
     * stylesheet.  The second can override the first.  At least one should be
     * given.
     */
    child_node = pcmk__xe_create(head_node, "style");
    pcmk__xe_set_content(child_node, "%s", stylesheet_default);

    if (stylesheet_link != NULL) {
        htmlNodePtr link_node = pcmk__xe_create(head_node, "link");

        pcmk__xe_set(link_node, "rel", "stylesheet");
        pcmk__xe_set(link_node, "href", stylesheet_link);
    }

    if (g_slist_length(priv->errors) > 0) {
        out->begin_list(out, "Errors", NULL, NULL);
        g_slist_foreach(priv->errors, add_error_node, (gpointer) out);
        out->end_list(out);
    }

    if (print) {
        htmlDocDump(out->dest, priv->root->doc);
    }

    if (copy_dest != NULL) {
        *copy_dest = pcmk__xml_copy(NULL, priv->root);
    }

    g_slist_free_full(extra_headers, (GDestroyNotify) pcmk__xml_free);
    extra_headers = NULL;
}

static void
html_reset(pcmk__output_t *out) {
    pcmk__assert(out != NULL);

    out->dest = freopen(NULL, "w", out->dest);
    pcmk__assert(out->dest != NULL);

    html_free_priv(out);
    html_init(out);
}

static void
html_subprocess_output(pcmk__output_t *out, int exit_status,
                       const char *proc_stdout, const char *proc_stderr) {
    char *rc_buf = NULL;

    pcmk__assert(out != NULL);

    rc_buf = pcmk__assert_asprintf("Return code: %d", exit_status);

    pcmk__output_create_xml_text_node(out, "h2", "Command Output");
    pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL, NULL, rc_buf);

    if (proc_stdout != NULL) {
        pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL, NULL, "Stdout");
        pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL,
                                      PCMK__VALUE_OUTPUT, proc_stdout);
    }
    if (proc_stderr != NULL) {
        pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL, NULL, "Stderr");
        pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL,
                                      PCMK__VALUE_OUTPUT, proc_stderr);
    }

    free(rc_buf);
}

static void
html_version(pcmk__output_t *out)
{
    pcmk__assert(out != NULL);

    pcmk__output_create_xml_text_node(out, "h2", "Version Information");
    pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL, NULL,
                                  "Program: Pacemaker");
    pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL, NULL,
                                  "Version: " PACEMAKER_VERSION);
    pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL, NULL,
                                  "Author: Andrew Beekhof and "
                                  "the Pacemaker project contributors");
    pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL, NULL,
                                  "Build: " BUILD_VERSION);
    pcmk__output_create_html_node(out, PCMK__XE_DIV, NULL, NULL,
                                  "Features: " CRM_FEATURES);
}

G_GNUC_PRINTF(2, 3)
static void
html_err(pcmk__output_t *out, const char *format, ...) {
    private_data_t *priv = NULL;
    int len = 0;
    char *buf = NULL;
    va_list ap;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    pcmk__assert(len >= 0);
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

    pcmk__assert(out != NULL);

    node = pcmk__output_create_html_node(out, "pre", NULL, NULL, buf);
    pcmk__xe_set(node, PCMK_XA_LANG, "xml");
}

G_GNUC_PRINTF(4, 5)
static void
html_begin_list(pcmk__output_t *out, const char *singular_noun,
                const char *plural_noun, const char *format, ...) {
    int q_len = 0;
    private_data_t *priv = NULL;
    xmlNodePtr node = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    /* If we are already in a list (the queue depth is always at least
     * one because of the <html> element), first create a <li> element
     * to hold the <h2> and the new list.
     */
    q_len = g_queue_get_length(priv->parent_q);
    if (q_len > 2) {
        pcmk__output_xml_create_parent(out, "li");
    }

    if (format != NULL) {
        va_list ap;
        char *buf = NULL;
        int len;

        va_start(ap, format);
        len = vasprintf(&buf, format, ap);
        va_end(ap);
        pcmk__assert(len >= 0);

        if (q_len > 2) {
            pcmk__output_create_xml_text_node(out, "h3", buf);
        } else {
            pcmk__output_create_xml_text_node(out, "h2", buf);
        }

        free(buf);
    }

    node = pcmk__output_xml_create_parent(out, "ul");

    // @FIXME This looks like an incorrect double-push; check this
    g_queue_push_tail(priv->parent_q, node);
}

G_GNUC_PRINTF(3, 4)
static void
html_list_item(pcmk__output_t *out, const char *name, const char *format, ...) {
    htmlNodePtr item_node = NULL;
    va_list ap;
    char *buf = NULL;
    int len;

    pcmk__assert(out != NULL);

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    pcmk__assert(len >= 0);
    va_end(ap);

    item_node = pcmk__output_create_xml_text_node(out, "li", buf);
    free(buf);

    if (name != NULL) {
        pcmk__xe_set(item_node, PCMK_XA_CLASS, name);
    }
}

static void
html_increment_list(pcmk__output_t *out) {
    /* This function intentially left blank */
}

static void
html_end_list(pcmk__output_t *out) {
    private_data_t *priv = NULL;

    pcmk__assert((out != NULL) && (out->priv != NULL));
    priv = out->priv;

    /* Remove the <ul> tag, but do not free this result - it's still
     * part of the document.
     */
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
    pcmk__assert(out != NULL);
    pcmk__output_create_xml_node(out, "br");
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

    pcmk__assert(out != NULL);
    CRM_CHECK(pcmk__str_eq(out->fmt_name, "html", pcmk__str_none), return NULL);

    node = pcmk__output_create_xml_text_node(out, element_name, text);

    if (class_name != NULL) {
        pcmk__xe_set(node, PCMK_XA_CLASS, class_name);
    }

    if (id != NULL) {
        pcmk__xe_set(node, PCMK_XA_ID, id);
    }

    return node;
}

/*!
 * \internal
 * \brief Create a new HTML element under a given parent with ID and class
 *
 * \param[in,out] parent      XML element that will be the new element's parent
 *                            (\c NULL to create a new XML document with the new
 *                            node as root)
 * \param[in]     name        Name of new element
 * \param[in]     id          CSS ID of new element (can be \c NULL)
 * \param[in]     class_name  CSS class of new element (can be \c NULL)
 *
 * \return Newly created XML element (guaranteed not to be \c NULL)
 */
xmlNode *
pcmk__html_create(xmlNode *parent, const char *name, const char *id,
                  const char *class_name)
{
    xmlNode *node = pcmk__xe_create(parent, name);

    pcmk__xe_set(node, PCMK_XA_CLASS, class_name);
    pcmk__xe_set(node, PCMK_XA_ID, id);
    return node;
}

void
pcmk__html_set_title(const char *name)
{
    g_free(title);
    title = g_strdup(name);
}

void
pcmk__html_add_header(const char *name, ...) {
    htmlNodePtr header_node;
    va_list ap;

    va_start(ap, name);

    header_node = pcmk__xe_create(NULL, name);
    while (1) {
        char *key = va_arg(ap, char *);
        char *value;

        if (key == NULL) {
            break;
        }

        value = va_arg(ap, char *);
        pcmk__xe_set(header_node, key, value);
    }

    extra_headers = g_slist_append(extra_headers, header_node);

    va_end(ap);
}
