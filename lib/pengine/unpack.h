/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PENGINE_UNPACK__H
#  define PENGINE_UNPACK__H

extern gboolean unpack_remote_nodes(xmlNode * xml_resources, pe_working_set_t * data_set);

extern gboolean unpack_resources(xmlNode * xml_resources, pe_working_set_t * data_set);

extern gboolean unpack_config(xmlNode * config, pe_working_set_t * data_set);

extern gboolean unpack_nodes(xmlNode * xml_nodes, pe_working_set_t * data_set);

extern gboolean unpack_tags(xmlNode * xml_tags, pe_working_set_t * data_set);

extern gboolean unpack_status(xmlNode * status, pe_working_set_t * data_set);

extern gint sort_op_by_callid(gconstpointer a, gconstpointer b);

extern gboolean unpack_lrm_resources(node_t * node, xmlNode * lrm_state,
                                     pe_working_set_t * data_set);

extern gboolean add_node_attrs(xmlNode * attrs, node_t * node, gboolean overwrite,
                               pe_working_set_t * data_set);

extern gboolean determine_online_status(xmlNode * node_state, node_t * this_node,
                                        pe_working_set_t * data_set);

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

// Some warnings we don't want to print every transition

enum pe_warn_once_e {
    pe_wo_blind         = 0x0001,
    pe_wo_restart_type  = 0x0002,
    pe_wo_role_after    = 0x0004,
    pe_wo_poweroff      = 0x0008,
    pe_wo_require_all   = 0x0010,
    pe_wo_order_score   = 0x0020,
};

extern uint32_t pe_wo;

#define pe_warn_once(pe_wo_bit, fmt...) do {    \
        if (is_not_set(pe_wo, pe_wo_bit)) {     \
            if (pe_wo_bit == pe_wo_blind) {     \
                crm_warn(fmt);                  \
            } else {                            \
                pe_warn(fmt);                   \
            }                                   \
            set_bit(pe_wo, pe_wo_bit);          \
        }                                       \
    } while (0);

#endif
