/*
 * Copyright 2015-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CURSES_INTERNAL_H
#  define CURSES_INTERNAL_H

#  include <stdio.h>

#  include <config.h>
#  include <crm/common/logging.h>

/*
 * The man pages for both curses and ncurses suggest inclusion of "curses.h".
 * We believe the following to be acceptable and portable.
 */

#  if defined(HAVE_LIBNCURSES) || defined(HAVE_LIBCURSES)
#    if defined(HAVE_NCURSES_H) && !defined(HAVE_INCOMPATIBLE_PRINTW)
#      include <ncurses.h>
#      define CURSES_ENABLED 1
#    elif defined(HAVE_NCURSES_NCURSES_H) && !defined(HAVE_INCOMPATIBLE_PRINTW)
#      include <ncurses/ncurses.h>
#      define CURSES_ENABLED 1
#    elif defined(HAVE_CURSES_H) && !defined(HAVE_INCOMPATIBLE_PRINTW)
#      include <curses.h>
#      define CURSES_ENABLED 1
#    elif defined(HAVE_CURSES_CURSES_H) && !defined(HAVE_INCOMPATIBLE_PRINTW)
#      include <curses/curses.h>
#      define CURSES_ENABLED 1
#    else
#      define CURSES_ENABLED 0
#    endif
#  else
#    define CURSES_ENABLED 0
#  endif

#  if CURSES_ENABLED
#    define status_printw(fmt, args...) printw(fmt, ##args)
#  else
#    define status_printw(fmt, args...) \
	crm_err("printw support requires ncurses to be available during configure"); \
	do_crm_log(LOG_WARNING, fmt, ##args);
#  endif

#  define status_print(fmt, args...)			\
	if(options & pe_print_html) {			\
		FILE *stream = print_data;		\
		fprintf(stream, fmt, ##args);		\
	} else if(options & pe_print_ncurses) {		\
		status_printw(fmt, ##args);		\
	} else if(options & pe_print_printf) {		\
		FILE *stream = print_data;		\
		fprintf(stream, fmt, ##args);		\
	} else if(options & pe_print_xml) {		\
		FILE *stream = print_data;		\
		fprintf(stream, fmt, ##args);		\
	} else if(options & pe_print_log) {		\
		int log_level = *(int*)print_data;	\
		do_crm_log(log_level, fmt, ##args);	\
	}

#endif
