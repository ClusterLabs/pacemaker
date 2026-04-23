/*
 * Copyright 2019-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_MON__H
#define CRM_MON__H

#include <crm_internal.h>

#include <glib.h>

#include <crm/common/internal.h>
#include <crm/common/scheduler.h>
#include <crm/stonith-ng.h>

/*
 * The man pages for both curses and ncurses suggest inclusion of "curses.h".
 * We believe the following to be acceptable and portable.
 */

#  if PCMK__ENABLE_CURSES
#    if defined(HAVE_NCURSES_H)
#      include <ncurses.h>
#    elif defined(HAVE_NCURSES_NCURSES_H)
#      include <ncurses/ncurses.h>
#    elif defined(HAVE_CURSES_H)
#      include <curses.h>
#    elif defined(HAVE_CURSES_CURSES_H)
#      include <curses/curses.h>
#    endif
#  endif

typedef enum {
    mon_output_unset,
    mon_output_none,
    mon_output_plain,
    mon_output_console,
    mon_output_xml,
    mon_output_legacy_xml,
    mon_output_html,
} mon_output_format_t;

enum mon_exec_mode {
    mon_exec_unset,
    mon_exec_daemonized,
    mon_exec_one_shot,
    mon_exec_update,
};

void crm_mon_register_messages(pcmk__output_t *out);

#if PCMK__ENABLE_CURSES
pcmk__output_t *crm_mon_mk_curses_output(char **argv);
void curses_formatted_printf(pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);
void curses_formatted_vprintf(pcmk__output_t *out, const char *format, va_list args) G_GNUC_PRINTF(2, 0);
void curses_indented_printf(pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);
void curses_indented_vprintf(pcmk__output_t *out, const char *format, va_list args) G_GNUC_PRINTF(2, 0);

#define CRM_MON_SUPPORTED_FORMAT_CURSES { "console", crm_mon_mk_curses_output, NULL }
#endif

#endif
