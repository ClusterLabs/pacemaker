/*
 * Copyright 2019-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdlib.h>

#include <glib.h>

#include <crm/crm.h>

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
    pcmk__assert(out != NULL);
    none_free_priv(out);
    none_init(out);
}

static void
none_subprocess_output(pcmk__output_t *out, int exit_status,
                       const char *proc_stdout, const char *proc_stderr) {
    /* This function intentionally left blank */
}

static void
none_version(pcmk__output_t *out)
{
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

void
pcmk__output_setup_none(pcmk__output_t *out)
{
    out->fmt_name = PCMK_VALUE_NONE;

    out->init = none_init;
    out->free_priv = none_free_priv;
    out->finish = none_finish;
    out->reset = none_reset;

    out->subprocess_output = none_subprocess_output;
    out->version = none_version;
    out->info = none_info;
    out->transient = none_info;
    out->err = none_err;
    out->output_xml = none_output_xml;

    out->begin_list = none_begin_list;
    out->list_item = none_list_item;
    out->increment_list = none_increment_list;
    out->end_list = none_end_list;

    out->is_quiet = none_is_quiet;
    out->spacer = none_spacer;
    out->progress = none_progress;
    out->prompt = none_prompt;
}
