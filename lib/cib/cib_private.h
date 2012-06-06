/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef CIB_PRIVATE__H
#  define CIB_PRIVATE__H

#  include <glib.h>

extern GHashTable *cib_op_callback_table;
typedef struct cib_notify_client_s {
    const char *event;
    const char *obj_id;         /* implement one day */
    const char *obj_type;       /* implement one day */
    void (*callback) (const char *event, xmlNode * msg);

} cib_notify_client_t;

typedef struct cib_callback_client_s {
    void (*callback) (xmlNode *, int, int, xmlNode *, void *);
    const char *id;
    void *user_data;
    gboolean only_success;
    struct timer_rec_s *timer;

} cib_callback_client_t;

struct timer_rec_s {
    int call_id;
    int timeout;
    guint ref;
    cib_t *cib;
};

typedef enum cib_errors (*cib_op_t) (const char *, int, const char *, xmlNode *,
                                     xmlNode *, xmlNode *, xmlNode **, xmlNode **);

extern cib_t *cib_new_variant(void);

enum cib_errors


cib_perform_op(const char *op, int call_options, cib_op_t * fn, gboolean is_query,
               const char *section, xmlNode * req, xmlNode * input,
               gboolean manage_counters, gboolean * config_changed,
               xmlNode * current_cib, xmlNode ** result_cib, xmlNode ** diff, xmlNode ** output);

extern xmlNode *cib_create_op(int call_id, const char *token, const char *op, const char *host,
                              const char *section, xmlNode * data, int call_options,
                              const char *user_name);

void cib_native_callback(cib_t * cib, xmlNode * msg, int call_id, int rc);
void cib_native_notify(gpointer data, gpointer user_data);
int cib_native_register_notification(cib_t * cib, const char *callback, int enabled);
gboolean cib_client_register_callback(cib_t * cib, int call_id, int timeout, gboolean only_success,
                                      void *user_data, const char *callback_name,
                                      void (*callback) (xmlNode *, int, int, xmlNode *, void *));

extern gboolean acl_enabled(GHashTable * config_hash);
extern gboolean acl_filter_cib(xmlNode * request, xmlNode * current_cib, xmlNode * orig_cib,
                               xmlNode ** filtered_cib);
extern gboolean acl_check_diff(xmlNode * request, xmlNode * current_cib, xmlNode * result_cib,
                               xmlNode * diff);

#endif
