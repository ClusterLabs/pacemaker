/*
 * Copyright 2018-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PE_STATUS_PRIVATE__H
#  define PE_STATUS_PRIVATE__H

/* This header is for the sole use of libpe_status, so that functions can be
 * declared with G_GNUC_INTERNAL for efficiency.
 */

#  if CURSES_ENABLED
#    define status_printw(fmt, args...) printw(fmt, ##args)
#  else
#    define status_printw(fmt, args...) \
   crm_err("printw support requires ncurses to be available during configure"); \
   do_crm_log(LOG_WARNING, fmt, ##args);
#  endif

#  define status_print(fmt, args...)           \
   if(options & pe_print_html) {           \
       FILE *stream = print_data;      \
       fprintf(stream, fmt, ##args);       \
   } else if(options & pe_print_ncurses) {     \
       status_printw(fmt, ##args);     \
   } else if(options & pe_print_printf) {      \
       FILE *stream = print_data;      \
       fprintf(stream, fmt, ##args);       \
   } else if(options & pe_print_xml) {     \
       FILE *stream = print_data;      \
       fprintf(stream, fmt, ##args);       \
   } else if(options & pe_print_log) {     \
       int log_level = *(int*)print_data;  \
       do_crm_log(log_level, fmt, ##args); \
   }

G_GNUC_INTERNAL
pe_resource_t *pe__create_clone_child(pe_resource_t *rsc,
                                      pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pe__force_anon(const char *standard, pe_resource_t *rsc, const char *rid,
                    pe_working_set_t *data_set);

G_GNUC_INTERNAL
gboolean unpack_remote_nodes(xmlNode *xml_resources, pe_working_set_t *data_set);

G_GNUC_INTERNAL
gboolean unpack_resources(xmlNode *xml_resources, pe_working_set_t *data_set);

G_GNUC_INTERNAL
gboolean unpack_config(xmlNode *config, pe_working_set_t *data_set);

G_GNUC_INTERNAL
gboolean unpack_nodes(xmlNode *xml_nodes, pe_working_set_t *data_set);

G_GNUC_INTERNAL
gboolean unpack_tags(xmlNode *xml_tags, pe_working_set_t *data_set);

G_GNUC_INTERNAL
gboolean unpack_status(xmlNode *status, pe_working_set_t *data_set);

#endif  // PE_STATUS_PRIVATE__H
