/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/common/internal.h>
#include <crm/common/output.h>
#include <libxml/tree.h>

static GHashTable *formatters = NULL;

void
pcmk__output_free(pcmk__output_t *out) {
    out->free_priv(out);

    if (out->messages != NULL) {
        g_hash_table_destroy(out->messages);
    }

    free(out->request);
    free(out);
}

int
pcmk__output_new(pcmk__output_t **out, const char *fmt_name, const char *filename,
                 char **argv) {
    pcmk__output_factory_t create = NULL;;

    if (formatters == NULL) {
        return EINVAL;
    }

    /* If no name was given, just try "text".  It's up to each tool to register
     * what it supports so this also may not be valid.
     */
    if (fmt_name == NULL) {
        create = g_hash_table_lookup(formatters, "text");
    } else {
        create = g_hash_table_lookup(formatters, fmt_name);
    }

    if (create == NULL) {
        return pcmk_err_unknown_format;
    }

    *out = create(argv);
    if (*out == NULL) {
        return ENOMEM;
    }

    if (filename == NULL || safe_str_eq(filename, "-")) {
        (*out)->dest = stdout;
    } else {
        (*out)->dest = fopen(filename, "w");
        if ((*out)->dest == NULL) {
            return errno;
        }
    }

    (*out)->messages = g_hash_table_new_full(crm_str_hash, g_str_equal, free, NULL);

    if ((*out)->init(*out) == false) {
        pcmk__output_free(*out);
        return ENOMEM;
    }

    return 0;
}

int
pcmk__register_format(GOptionGroup *group, const char *name,
                      pcmk__output_factory_t create, GOptionEntry *options) {
    if (create == NULL) {
        return -EINVAL;
    }

    if (formatters == NULL) {
        formatters = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, NULL);
    }

    if (options != NULL && group != NULL) {
        g_option_group_add_entries(group, options);
    }

    g_hash_table_insert(formatters, strdup(name), create);
    return 0;
}

void
pcmk__register_formats(GOptionGroup *group, pcmk__supported_format_t *formats) {
    pcmk__supported_format_t *entry = NULL;

    if (formats == NULL) {
        return;
    }

    for (entry = formats; entry->name != NULL; entry++) {
        pcmk__register_format(group, entry->name, entry->create, entry->options);
    }
}

int
pcmk__call_message(pcmk__output_t *out, const char *message_id, ...) {
    va_list args;
    int rc = 0;
    pcmk__message_fn_t fn;

    fn = g_hash_table_lookup(out->messages, message_id);
    if (fn == NULL) {
        return -EINVAL;
    }

    va_start(args, message_id);
    rc = fn(out, args);
    va_end(args);

    return rc;
}

void
pcmk__register_message(pcmk__output_t *out, const char *message_id,
                       pcmk__message_fn_t fn) {
    g_hash_table_replace(out->messages, strdup(message_id), fn);
}

void
pcmk__register_messages(pcmk__output_t *out, pcmk__message_entry_t *table) {
    pcmk__message_entry_t *entry;

    for (entry = table; entry->message_id != NULL; entry++) {
        if (safe_str_eq(out->fmt_name, entry->fmt_name)) {
            pcmk__register_message(out, entry->message_id, entry->fn);
        }
    }
}
