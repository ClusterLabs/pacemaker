/*
 * Copyright 2015-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CURSES_INTERNAL__H
#  define PCMK__CURSES_INTERNAL__H

#  include <stdio.h>

#  ifndef PCMK__CONFIG_H
#    define PCMK__CONFIG_H
#    include <config.h>
#  endif

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

#endif
