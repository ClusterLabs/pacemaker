/*
 * Copyright (c) 2004 International Business Machines
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
 *
 */
#include <crm_internal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <sys/stat.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>

#define cib_flag_dirty 0x00001

typedef struct cib_file_opaque_s {
    int flags;
    char *filename;

} cib_file_opaque_t;

int cib_file_perform_op(cib_t * cib, const char *op, const char *host, const char *section,
                        xmlNode * data, xmlNode ** output_data, int call_options);

int cib_file_perform_op_delegate(cib_t * cib, const char *op, const char *host, const char *section,
                                 xmlNode * data, xmlNode ** output_data, int call_options,
                                 const char *user_name);

int cib_file_signon(cib_t * cib, const char *name, enum cib_conn_type type);
int cib_file_signoff(cib_t * cib);
int cib_file_free(cib_t * cib);

static int
cib_file_inputfd(cib_t * cib)
{
    return -EPROTONOSUPPORT;
}

static int
cib_file_set_connection_dnotify(cib_t * cib, void (*dnotify) (gpointer user_data))
{
    return -EPROTONOSUPPORT;
}

static int
cib_file_register_notification(cib_t * cib, const char *callback, int enabled)
{
    return -EPROTONOSUPPORT;
}

cib_t *
cib_file_new(const char *cib_location)
{
    cib_file_opaque_t *private = NULL;
    cib_t *cib = cib_new_variant();

    private = calloc(1, sizeof(cib_file_opaque_t));

    cib->variant = cib_file;
    cib->variant_opaque = private;

    if (cib_location == NULL) {
        cib_location = getenv("CIB_file");
    }
    private->flags = 0;
    private->filename = strdup(cib_location);

    /* assign variant specific ops */
    cib->delegate_fn = cib_file_perform_op_delegate;
    cib->cmds->signon = cib_file_signon;
    cib->cmds->signoff = cib_file_signoff;
    cib->cmds->free = cib_file_free;
    cib->cmds->inputfd = cib_file_inputfd;

    cib->cmds->register_notification = cib_file_register_notification;
    cib->cmds->set_connection_dnotify = cib_file_set_connection_dnotify;

    return cib;
}

static xmlNode *in_mem_cib = NULL;
static int
load_file_cib(const char *filename)
{
    int rc = pcmk_ok;
    struct stat buf;
    xmlNode *root = NULL;
    gboolean dtd_ok = TRUE;
    const char *ignore_dtd = NULL;
    xmlNode *status = NULL;

    rc = stat(filename, &buf);
    if (rc == 0) {
        root = filename2xml(filename);
        if (root == NULL) {
            return -pcmk_err_schema_validation;
        }

    } else {
        return -ENXIO;
    }

    rc = 0;

    status = find_xml_node(root, XML_CIB_TAG_STATUS, FALSE);
    if (status == NULL) {
        create_xml_node(root, XML_CIB_TAG_STATUS);
    }

    ignore_dtd = crm_element_value(root, XML_ATTR_VALIDATION);
    dtd_ok = validate_xml(root, NULL, TRUE);
    if (dtd_ok == FALSE) {
        crm_err("CIB does not validate against %s", ignore_dtd);
        rc = -pcmk_err_schema_validation;
        goto bail;
    }

    in_mem_cib = root;
    return rc;

  bail:
    free_xml(root);
    root = NULL;
    return rc;
}

int
cib_file_signon(cib_t * cib, const char *name, enum cib_conn_type type)
{
    int rc = pcmk_ok;
    cib_file_opaque_t *private = cib->variant_opaque;

    private->flags = 0;
    if (private->filename == FALSE) {
        rc = -EINVAL;
    } else {
        rc = load_file_cib(private->filename);
    }

    if (rc == pcmk_ok) {
        crm_debug("%s: Opened connection to local file '%s'", name, private->filename);
        cib->state = cib_connected_command;
        cib->type = cib_command;

    } else {
        fprintf(stderr, "%s: Connection to local file '%s' failed: %s\n",
                name, private->filename, pcmk_strerror(rc));
    }

    return rc;
}

int
cib_file_signoff(cib_t * cib)
{
    int rc = pcmk_ok;
    cib_file_opaque_t *private = cib->variant_opaque;

    crm_debug("Signing out of the CIB Service");

    cib->state = cib_disconnected;
    cib->type = cib_no_connection;

    if(is_not_set(private->flags, cib_flag_dirty)) {
        /* No changes to write out */
        free_xml(in_mem_cib);
        return pcmk_ok;

    } else if (strstr(private->filename, ".bz2") != NULL) {
        rc = write_xml_file(in_mem_cib, private->filename, TRUE);

    } else {
        rc = write_xml_file(in_mem_cib, private->filename, FALSE);
    }

    if (rc > 0) {
        crm_info("Wrote CIB to %s", private->filename);
        rc = pcmk_ok;

    } else {
        crm_err("Could not write CIB to %s: %s (%d)", private->filename, pcmk_strerror(rc), rc);
    }
    free_xml(in_mem_cib);

    return rc;
}

int
cib_file_free(cib_t * cib)
{
    int rc = pcmk_ok;

    if (cib->state != cib_disconnected) {
        rc = cib_file_signoff(cib);
    }

    if (rc == pcmk_ok) {
        cib_file_opaque_t *private = cib->variant_opaque;

        free(private->filename);
        free(cib->cmds);
        free(private);
        free(cib);

    } else {
        fprintf(stderr, "Couldn't sign off: %d\n", rc);
    }

    return rc;
}

struct cib_func_entry {
    const char *op;
    gboolean read_only;
    cib_op_t fn;
};

/* *INDENT-OFF* */
static struct cib_func_entry cib_file_ops[] = {
    {CIB_OP_QUERY,      TRUE,  cib_process_query},
    {CIB_OP_MODIFY,     FALSE, cib_process_modify},
    {CIB_OP_APPLY_DIFF, FALSE, cib_process_diff},
    {CIB_OP_BUMP,       FALSE, cib_process_bump},
    {CIB_OP_REPLACE,    FALSE, cib_process_replace},
    {CIB_OP_CREATE,     FALSE, cib_process_create},
    {CIB_OP_DELETE,     FALSE, cib_process_delete},
    {CIB_OP_ERASE,      FALSE, cib_process_erase},
    {CIB_OP_UPGRADE,    FALSE, cib_process_upgrade},
};
/* *INDENT-ON* */

int
cib_file_perform_op(cib_t * cib, const char *op, const char *host, const char *section,
                    xmlNode * data, xmlNode ** output_data, int call_options)
{
    return cib_file_perform_op_delegate(cib, op, host, section, data, output_data, call_options,
                                        NULL);
}

int
cib_file_perform_op_delegate(cib_t * cib, const char *op, const char *host, const char *section,
                             xmlNode * data, xmlNode ** output_data, int call_options,
                             const char *user_name)
{
    int rc = pcmk_ok;
    char *effective_user = NULL;
    gboolean query = FALSE;
    gboolean changed = FALSE;
    xmlNode *request = NULL;
    xmlNode *output = NULL;
    xmlNode *cib_diff = NULL;
    xmlNode *result_cib = NULL;
    cib_op_t *fn = NULL;
    int lpc = 0;
    static int max_msg_types = DIMOF(cib_file_ops);
    cib_file_opaque_t *private = cib->variant_opaque;

    crm_info("%s on %s", op, section);
    call_options |= (cib_no_mtime | cib_inhibit_bcast | cib_scope_local);

    if (cib->state == cib_disconnected) {
        return -ENOTCONN;
    }

    if (output_data != NULL) {
        *output_data = NULL;
    }

    if (op == NULL) {
        return -EINVAL;
    }

    for (lpc = 0; lpc < max_msg_types; lpc++) {
        if (safe_str_eq(op, cib_file_ops[lpc].op)) {
            fn = &(cib_file_ops[lpc].fn);
            query = cib_file_ops[lpc].read_only;
            break;
        }
    }

    if (fn == NULL) {
        return -EPROTONOSUPPORT;
    }

    cib->call_id++;
    request = cib_create_op(cib->call_id, "dummy-token", op, host, section, data, call_options, user_name);
#if ENABLE_ACL
    if(user_name) {
        crm_xml_add(request, XML_ACL_TAG_USER, user_name);
    }
    crm_trace("Performing %s operation as %s", op, user_name);
#endif

    /* Mirror the logic in cib_prepare_common() */
    if (section != NULL && data != NULL && crm_str_eq(crm_element_name(data), XML_TAG_CIB, TRUE)) {
        data = get_object_root(section, data);
    }

    rc = cib_perform_op(op, call_options, fn, query,
                        section, request, data, TRUE, &changed, in_mem_cib, &result_cib, &cib_diff,
                        &output);

    free_xml(request);
    if (rc == -pcmk_err_schema_validation) {
        validate_xml_verbose(result_cib);
    }

    if (rc != pcmk_ok) {
        free_xml(result_cib);

    } else if (query == FALSE) {
        xml_log_patchset(LOG_DEBUG, "cib:diff", cib_diff);
        free_xml(in_mem_cib);
        in_mem_cib = result_cib;
        private->flags |= cib_flag_dirty;
    }

    free_xml(cib_diff);

    if (cib->op_callback != NULL) {
        cib->op_callback(NULL, cib->call_id, rc, output);
    }

    if (output_data && output) {
        if(output == in_mem_cib) {
            *output_data = copy_xml(output);
        } else {
            *output_data = output;
        }

    } else if(output != in_mem_cib) {
        free_xml(output);
    }

    free(effective_user);
    return rc;
}
