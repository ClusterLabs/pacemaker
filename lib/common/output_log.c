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

typedef struct private_log_message_attr_s {
    uint8_t log_level;
    char filename[LINE_MAX];
    char function[LINE_MAX];
    uint32_t lineno;
} private_log_message_attr_t;

/* A log message consists of the text itself, level of
 * severity and location in the source code where it
 * was called.
 * The attributes of messages are first set by two message
 * functions "set_log_level" and "set_file_func_line"
 * in a private_data_t instance. Then, when creating
 * an instance of private_log_message_t those attributes
 * are simply copied from the private_data_t.
 */
typedef struct private_log_message_s {
    private_log_message_attr_t attr;
    char* text;
} private_log_message_t;

typedef struct private_data_s {
    private_log_message_attr_t attr;
    GList/*<char*>*/ *prefixes; /* gathered in log_begin_list */
    GQueue/*<private_log_message_t>*/ *messages;
} private_data_t;

static void
log_output_message(private_log_message_t *message) {
    qb_log_from_external_source(message->attr.function
                                , message->attr.filename
                                , "%s"
                                , message->attr.log_level
                                , message->attr.lineno
                                , 0
                                , message->text);
}

static void
log_subprocess_output(pcmk__output_t *out, int exit_status,
                      const char *proc_stdout, const char *proc_stderr) {
    private_log_message_t message;
    message.attr = ((private_data_t *)out->priv)->attr;
    CRM_ASSERT(out && out->priv);
    if (proc_stdout != NULL) {
        message.text = (char *)proc_stdout;
        log_output_message(&message);
    }

    if (proc_stderr != NULL) {
        message.text = (char *)proc_stderr;
        log_output_message(&message);
    }
}

static void
log_free_priv(pcmk__output_t *out) {
    private_data_t *priv = out->priv;

    if (priv == NULL) {
        return;
    }

    for(GList* gIter = priv->messages->head; gIter; gIter = gIter->next) {
        free(((private_log_message_t*)gIter->data)->text);
    }
    g_queue_free(priv->messages);
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

    ((private_data_t *)out->priv)->attr.log_level = LOG_INFO;
    ((private_data_t *)out->priv)->messages = g_queue_new();
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

G_GNUC_PRINTF(2, 3)
static void
pcmk__output_crm_log(pcmk__output_t *out, const char *format, ...) {
    int len = 0;
    va_list ap;
    private_log_message_t *message = calloc(1, sizeof(private_log_message_t));
    const private_data_t *priv = NULL;
    CRM_ASSERT(message != NULL);
    CRM_ASSERT(out && out->priv);
    priv = (private_data_t *)out->priv;

    message->attr.log_level = priv->attr.log_level;
    strcpy(message->attr.filename, priv->attr.filename);
    strcpy(message->attr.function, priv->attr.function);
    message->attr.lineno = priv->attr.lineno;

    va_start(ap, format);
    len = vasprintf(&message->text, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    /* save the message for future use */
    g_queue_push_tail(priv->messages, message);
    /* and print it now */
    log_output_message(message);
}

static void
log_version(pcmk__output_t *out, bool extended) {
    /* Make sure the out->attr is already set */
    if (extended) {
        pcmk__output_crm_log(out, "Pacemaker %s (Build: %s): %s\n",
                   PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
    } else {
        pcmk__output_crm_log(out, "Pacemaker %s\n", PACEMAKER_VERSION);
        pcmk__output_crm_log(out, "Written by Andrew Beekhof\n");
    }
}

G_GNUC_PRINTF(2, 3)
static void
log_err(pcmk__output_t *out, const char *format, ...) {
    va_list ap;
    char* buffer = NULL;
    int len = 0;
    uint8_t log_level;
    private_data_t *priv = NULL;

    CRM_ASSERT(out && out->priv);
    va_start(ap, format);

    /* Informational output does not get indented, to separate it from other
     * potentially indented list output.
     */
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    priv = (private_data_t *)out->priv;
    /* backup the log_level*/
    log_level = priv->attr.log_level;
    priv->attr.log_level = LOG_ERR;
    /* print out the log message with the LOG_ERR severity */
    pcmk__output_crm_log(out, "%s", buffer);
    /* restore the log_level backup */
    priv->attr.log_level = log_level;
    free(buffer);
}

static void
log_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    private_data_t *priv = out->priv;
    xmlNodePtr node = NULL;

    CRM_ASSERT(priv != NULL);

    node = create_xml_node(NULL, name);
    xmlNodeSetContent(node, (pcmkXmlStr) buf);
    do_crm_log_xml(priv->attr.log_level, name, node);
    free(node);
}

G_GNUC_PRINTF(4, 5)
static void
log_begin_list(pcmk__output_t *out, const char *singular_noun, const char *plural_noun,
               const char *format, ...) {
    int len = 0;
    va_list ap;
    private_data_t *priv = out->priv;
    char* buffer = NULL;
    CRM_ASSERT(priv != NULL);

    va_start(ap, format);
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    if(strcmp(buffer, "") != 0) { /* We don't want empty prefixes */
        priv->prefixes = g_list_append(priv->prefixes, crm_strdup_printf("%s", buffer));
    }
    free(buffer);
}

G_GNUC_PRINTF(3, 4)
static void
log_list_item(pcmk__output_t *out, const char *name, const char *format, ...) {
    int len = 0;
    va_list ap;
    private_data_t *priv = out->priv;
    const char *priority = NULL;
    char prefix[LINE_MAX] = { 0 };
    int offset = 0;
    char* buffer = NULL;

    CRM_ASSERT(priv != NULL);

    priority = crm_int2priority(priv->attr.log_level);
    CRM_ASSERT(priority != NULL);

    for (GList* gIter = priv->prefixes; gIter; gIter = gIter->next) {
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
                pcmk__output_crm_log(out, "%s: %s: %s: %s", priority, prefix, name, buffer);
            } else {
                pcmk__output_crm_log(out, "%s: %s: %s", priority, name, buffer);
            }
        } else {
            if (strcmp(prefix, "") != 0) {
                pcmk__output_crm_log(out, "%s: %s: %s", priority, prefix, buffer);
            } else {
                pcmk__output_crm_log(out, "%s: %s", priority, buffer);
            }
        }
    }
    free(buffer);
}

static void
log_end_list(pcmk__output_t *out) {
    private_data_t *priv = out->priv;
    GList *last_prefix = NULL;
    CRM_ASSERT(priv != NULL);
    if (priv->prefixes == NULL) {
      return;
    }
    last_prefix = g_list_last(priv->prefixes);
    CRM_ASSERT(last_prefix != NULL);

    free((char *)last_prefix->data);
    priv->prefixes = g_list_remove(priv->prefixes, last_prefix->data);
}

G_GNUC_PRINTF(2, 3)
static void
log_info(pcmk__output_t *out, const char *format, ...) {
    int len = 0;
    va_list ap;
    char* buffer = NULL;
    uint8_t log_level;
    private_data_t *priv = out->priv;
    CRM_ASSERT(priv != NULL);

    va_start(ap, format);
    len = vasprintf(&buffer, format, ap);
    CRM_ASSERT(len >= 0);
    va_end(ap);

    log_level = priv->attr.log_level;
    priv->attr.log_level = LOG_INFO;
    log_list_item(out, NULL, "%s", buffer);
    priv->attr.log_level = log_level;

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

void
pcmk__output_set_file_func_line(pcmk__output_t *out, const char *filename
                                , const char *function, uint32_t lineno) {
    private_data_t *priv = (private_data_t *)out->priv;
    CRM_ASSERT(priv != NULL);

    strncpy(priv->attr.filename, filename, LINE_MAX-1);
    strncpy(priv->attr.function, function, LINE_MAX-1);
    priv->attr.lineno = lineno;
}
