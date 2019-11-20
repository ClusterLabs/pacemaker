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

GOptionEntry pcmk__log_output_entries[] = {
    { NULL }
};

typedef struct private_data_s {
    /* gathered in log_begin_list */
    GQueue/*<char*>*/ *prefixes;
} private_data_t;

static void
log_subprocess_output(pcmk__output_t *out, int exit_status,
                      const char *proc_stdout, const char *proc_stderr) {
    /* This function intentionally left blank */
}

static void
log_free_priv(pcmk__output_t *out) {
    private_data_t *priv = out->priv;

    if (priv == NULL) {
        return;
    }

    g_queue_free(priv->prefixes);
    free(priv);
}

static bool
log_init(pcmk__output_t *out) {

    /* If log_init was previously called on this output struct, just return. */
    if (out->priv != NULL) {
        return true;
    }

    out->priv = calloc(1, sizeof(private_data_t));
    if (out->priv == NULL) {
         return false;
    }
    ((private_data_t *)out->priv)->prefixes = g_queue_new();
    return true;
}

static void
log_finish(pcmk__output_t *out, crm_exit_t exit_status, bool print, void **copy_dest) {
    /* This function intentionally left blank */
}

static void
log_reset(pcmk__output_t *out) {
    CRM_ASSERT(out && out->priv);

    log_free_priv(out);
    log_init(out);
}

static void
log_version(pcmk__output_t *out, bool extended) {
    if (extended) {
        crm_info("Pacemaker %s (Build: %s): %s",
                   PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
    } else {
        crm_info("Pacemaker %s", PACEMAKER_VERSION);
        crm_info("Written by Andrew Beekhof");
    }
}

G_GNUC_PRINTF(2, 3)
static void
log_err(pcmk__output_t *out, const char *format, ...) {
    va_list ap;
    char* buffer = NULL;
    int len = 0;

    va_start(ap, format);
    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    crm_err("%s", buffer);

    free(buffer);
}

static void
log_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    xmlNodePtr node = NULL;
    private_data_t *priv = out->priv;
    CRM_ASSERT(priv != NULL);

    node = create_xml_node(NULL, name);
    xmlNodeSetContent(node, (pcmkXmlStr) buf);
    do_crm_log_xml(LOG_INFO, name, node);
    free(node);
}

G_GNUC_PRINTF(4, 5)
static void
log_begin_list(pcmk__output_t *out, const char *singular_noun, const char *plural_noun,
               const char *format, ...) {
    int len = 0;
    va_list ap;
    char* buffer = NULL;
    private_data_t *priv = out->priv;
    CRM_ASSERT(priv != NULL);

    va_start(ap, format);
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    /* Don't skip empty prefixes,
     * otherwise there will be mismatch
     * in the log_end_list */
    if(strcmp(buffer, "") == 0) {
        /* nothing */
    }

    g_queue_push_tail(priv->prefixes, buffer);
}

G_GNUC_PRINTF(3, 4)
static void
log_list_item(pcmk__output_t *out, const char *name, const char *format, ...) {
    int len = 0;
    va_list ap;
    private_data_t *priv = out->priv;
    char prefix[LINE_MAX] = { 0 };
    int offset = 0;
    char* buffer = NULL;

    CRM_ASSERT(priv != NULL);

    for (GList* gIter = priv->prefixes->head; gIter; gIter = gIter->next) {
        if (strcmp(prefix, "") != 0) {
            offset += snprintf(prefix + offset, LINE_MAX - offset, ": %s", (char *)gIter->data);
        } else {
            offset = snprintf(prefix, LINE_MAX, "%s", (char *)gIter->data);
        }
    }

    va_start(ap, format);
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    if (strcmp(buffer, "") != 0) { /* We don't want empty messages */
        if ((name != NULL) && (strcmp(name, "") != 0)) {
            if (strcmp(prefix, "") != 0) {
                crm_info("%s: %s: %s", prefix, name, buffer);
            } else {
                crm_info("%s: %s", name, buffer);
            }
        } else {
            if (strcmp(prefix, "") != 0) {
                crm_info("%s: %s", prefix, buffer);
            } else {
                crm_info("%s", buffer);
            }
        }
    }
    free(buffer);
}

static void
log_end_list(pcmk__output_t *out) {
    private_data_t *priv = out->priv;
    CRM_ASSERT(priv != NULL);
    if (priv->prefixes == NULL) {
      return;
    }
    CRM_ASSERT(priv->prefixes->tail != NULL);

    free((char *)priv->prefixes->tail->data);
    g_queue_pop_tail(priv->prefixes);
}

G_GNUC_PRINTF(2, 3)
static void
log_info(pcmk__output_t *out, const char *format, ...) {
    int len = 0;
    va_list ap;
    char* buffer = NULL;

    va_start(ap, format);
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    crm_info("%s", buffer);

    free(buffer);
}

pcmk__output_t *
pcmk__mk_log_output(char **argv) {
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->fmt_name = "log";
    retval->request = g_strjoinv(" ", argv);
    retval->supports_quiet = false;

    retval->init = log_init;
    retval->free_priv = log_free_priv;
    retval->finish = log_finish;
    retval->reset = log_reset;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->subprocess_output = log_subprocess_output;
    retval->version = log_version;
    retval->info = log_info;
    retval->err = log_err;
    retval->output_xml = log_output_xml;

    retval->begin_list = log_begin_list;
    retval->list_item = log_list_item;
    retval->end_list = log_end_list;

    return retval;
}
