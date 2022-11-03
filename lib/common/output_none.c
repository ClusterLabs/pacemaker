/*
 * Copyright 2019-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdlib.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/common/cmdline_internal.h>

GOptionEntry pcmk__none_output_entries[] = {
    { NULL }
};

static void
none_free_priv(pcmk__output_t *out) {
    /* This function intentionally left blank */
}

static bool
none_init(pcmk__output_t *out) {
    return true;
}

static void
none_finish(pcmk__output_t *out, crm_exit_t exit_status, bool print, void **copy_dest) {
    /* This function intentionally left blank */
}

static void
none_reset(pcmk__output_t *out) {
    CRM_ASSERT(out != NULL);
    none_free_priv(out);
    none_init(out);
}

static void
none_subprocess_output(pcmk__output_t *out, int exit_status,
                       const char *proc_stdout, const char *proc_stderr) {
    /* This function intentionally left blank */
}

static void
none_version(pcmk__output_t *out, bool extended) {
    /* This function intentionally left blank */
}

G_GNUC_PRINTF(2, 3)
static void
none_err(pcmk__output_t *out, const char *format, ...) {
    /* This function intentionally left blank */
}

G_GNUC_PRINTF(2, 3)
static int
none_info(pcmk__output_t *out, const char *format, ...) {
    return pcmk_rc_no_output;
}

static void
none_output_xml(pcmk__output_t *out, const char *name, const char *buf) {
    /* This function intentionally left blank */
}

G_GNUC_PRINTF(4, 5)
static void
none_begin_list(pcmk__output_t *out, const char *singular_noun, const char *plural_noun,
                const char *format, ...) {
    /* This function intentionally left blank */
}

G_GNUC_PRINTF(3, 4)
static void
none_list_item(pcmk__output_t *out, const char *id, const char *format, ...) {
    /* This function intentionally left blank */
}

static void
none_increment_list(pcmk__output_t *out) {
    /* This function intentionally left blank */
}

static void
none_end_list(pcmk__output_t *out) {
    /* This function intentionally left blank */
}

static bool
none_is_quiet(pcmk__output_t *out) {
    return out->quiet;
}

static void
none_spacer(pcmk__output_t *out) {
    /* This function intentionally left blank */
}

static void
none_progress(pcmk__output_t *out, bool end) {
    /* This function intentionally left blank */
}

static void
none_prompt(const char *prompt, bool echo, char **dest) {
    /* This function intentionally left blank */
}

pcmk__output_t *
pcmk__mk_none_output(char **argv) {
    pcmk__output_t *retval = calloc(1, sizeof(pcmk__output_t));

    if (retval == NULL) {
        return NULL;
    }

    retval->fmt_name = PCMK__VALUE_NONE;
    retval->request = pcmk__quote_cmdline(argv);

    retval->init = none_init;
    retval->free_priv = none_free_priv;
    retval->finish = none_finish;
    retval->reset = none_reset;

    retval->register_message = pcmk__register_message;
    retval->message = pcmk__call_message;

    retval->subprocess_output = none_subprocess_output;
    retval->version = none_version;
    retval->info = none_info;
    retval->transient = none_info;
    retval->err = none_err;
    retval->output_xml = none_output_xml;

    retval->begin_list = none_begin_list;
    retval->list_item = none_list_item;
    retval->increment_list = none_increment_list;
    retval->end_list = none_end_list;

    retval->is_quiet = none_is_quiet;
    retval->spacer = none_spacer;
    retval->progress = none_progress;
    retval->prompt = none_prompt;

    return retval;
}
