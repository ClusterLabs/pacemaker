/*
 * Copyright 2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <ftw.h>
#include <unistd.h>
#include <sys/stat.h>

#include <crm/cib.h>
#include <crm/cib/cib_types.h>
#include <crm/cib/internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/mainloop.h>

#include "pacemaker-execd.h"

static pid_t schema_fetch_pid = 0;

static int
rm_files(const char *pathname, const struct stat *sbuf, int type, struct FTW *ftwb)
{
    /* Don't delete PCMK__REMOTE_SCHEMA_DIR . */
    if (ftwb->level == 0) {
        return 0;
    }

    if (remove(pathname) != 0) {
        int rc = errno;
        crm_err("Could not remove %s: %s", pathname, pcmk_rc_str(rc));
        return -1;
    }

    return 0;
}

static void
clean_up_extra_schema_files(void)
{
    const char *remote_schema_dir = pcmk__remote_schema_dir();
    struct stat sb;
    int rc;

    rc = stat(remote_schema_dir, &sb);

    if (rc == -1) {
        if (errno == ENOENT) {
            /* If the directory doesn't exist, try to make it first. */
            if (mkdir(remote_schema_dir, 0755) != 0) {
                rc = errno;
                crm_err("Could not create directory for schemas: %s",
                        pcmk_rc_str(rc));
            }

        } else {
            rc = errno;
            crm_err("Could not create directory for schemas: %s",
                    pcmk_rc_str(rc));
        }

    } else if (!S_ISDIR(sb.st_mode)) {
        /* If something exists with the same name that's not a directory, that's
         * an error.
         */
        crm_err("%s already exists but is not a directory", remote_schema_dir);

    } else {
        /* It's a directory - clear it out so we can download potentially new
         * schema files.
         */
        rc = nftw(remote_schema_dir, rm_files, 10, FTW_DEPTH|FTW_MOUNT|FTW_PHYS);

        if (rc != 0) {
            crm_err("Could not remove %s: %s", remote_schema_dir, pcmk_rc_str(rc));
        }
    }
}

static void
write_extra_schema_file(xmlNode *xml, void *user_data)
{
    const char *remote_schema_dir = pcmk__remote_schema_dir();
    const char *file = NULL;
    char *path = NULL;
    int rc;

    file = crm_element_value(xml, PCMK__XA_PATH);
    if (file == NULL) {
        crm_warn("No destination path given in schema request");
        return;
    }

    path = crm_strdup_printf("%s/%s", remote_schema_dir, file);

    /* The schema is a CDATA node, which is a child of the <file> node.  Traverse
     * all children and look for the first CDATA child.  There can't be more than
     * one because we only have one file attribute on the parent.
     */
    for (xmlNode *child = xml->children; child != NULL; child = child->next) {
        FILE *stream = NULL;

        if (child->type != XML_CDATA_SECTION_NODE) {
            continue;
        }

        stream = fopen(path, "w+");
        if (stream == NULL) {
            crm_warn("Could not write schema file %s: %s", path, strerror(errno));
        } else {
            rc = fprintf(stream, "%s", child->content);

            if (rc < 0) {
                crm_warn("Could not write schema file %s: %s", path, strerror(errno));
            }

            fclose(stream);
        }

        break;
    }

    free(path);
}

static void
get_schema_files(void)
{
    int rc = pcmk_rc_ok;
    cib_t *cib = NULL;
    xmlNode *reply;

    cib = cib_new();
    if (cib == NULL) {
        _exit(ENOTCONN);
    }

    rc = cib->cmds->signon(cib, crm_system_name, cib_query);
    if (rc != pcmk_ok) {
        crm_err("Could not connect to the CIB manager: %s", pcmk_strerror(rc));
        _exit(pcmk_rc2exitc(rc));
    }

    rc = cib->cmds->fetch_schemas(cib, &reply, xml_latest_schema(), cib_sync_call);
    if (rc != pcmk_ok) {
        crm_err("Could not get schema files: %s", pcmk_strerror(rc));
        rc = pcmk_legacy2rc(rc);

    } else if (reply->children != NULL) {
        /* The returned document looks something like this:
         * <cib_command>
         *   <cib_calldata>
         *     <schemas>
         *       <schema version="pacemaker-1.1">
         *         <file path="foo-1.1">
         *         </file>
         *         <file path="bar-1.1">
         *         </file>
         *         ...
         *       </schema>
         *       <schema version="pacemaker-1.2">
         *       </schema>
         *       ...
         *     </schemas>
         *   </cib_calldata>
         * </cib_command>
         *
         * All the <schemas> and <schema> tags are really just there for organizing
         * the XML a little better.  What we really care about are the <file> nodes,
         * and specifically the path attributes and the CDATA children (not shown)
         * of each.  We can use an xpath query to reach down and get all the <file>
         * nodes at once.
         *
         * If we already have the latest schema version, or we asked for one later
         * than what the cluster supports, we'll get back an empty <schemas> node,
         * so all this will continue to work.  It just won't do anything.
         */
        crm_foreach_xpath_result(reply, "//" PCMK__XA_FILE, write_extra_schema_file, NULL);
    }

    cib__clean_up_connection(&cib);
    _exit(pcmk_rc2exitc(rc));
}

/* Load any additional schema files when the child is finished fetching and
 * saving them to disk.
 */
static void
get_schema_files_complete(mainloop_child_t *p, pid_t pid, int core, int signo, int exitcode)
{
    const char *errmsg = "Could not load additional schema files";

    if ((signo == 0) && (exitcode == 0)) {
        const char *remote_schema_dir = pcmk__remote_schema_dir();

        /* Don't just crm_schema_init here because that will load the base
         * schemas again too.  Instead just load the things we fetched.
         */
        pcmk__load_schemas_from_dir(remote_schema_dir);
        pcmk__sort_schemas();
        crm_info("Fetching extra schema files completed successfully");

    } else {
        if (signo == 0) {
            crm_err("%s: process %d exited %d", errmsg, (int) pid, exitcode);

        } else {
            crm_err("%s: process %d terminated with signal %d (%s)%s",
                    errmsg, (int) pid, signo, strsignal(signo),
                    (core? " and dumped core" : ""));
        }

        /* Clean up any incomplete schema data we might have been downloading when
         * the process timed out or crashed.  We don't need to do any extra cleanup
         * because we never loaded the extra schemas, and we don't need to call
         * crm_schema_init because that was called in remoted_request_cib_schema_files
         * before this function.
         */
        clean_up_extra_schema_files();
    }
}

void
remoted_request_cib_schema_files(void)
{
    pid_t pid;
    int rc;

    /* If a previous schema-fetch process is still running when we're called
     * again, it's hung.  Attempt to kill it before cleaning up the extra
     * directory.
     */
    if (schema_fetch_pid != 0) {
        if (mainloop_child_kill(schema_fetch_pid) == FALSE) {
            crm_warn("Unable to kill pre-existing schema-fetch process");
            return;
        }

        schema_fetch_pid = 0;
    }

    /* Clean up any extra schema files we downloaded from a previous cluster
     * connection.  After the files are gone, we need to wipe them from
     * known_schemas, but there's no opposite operation for add_schema().
     *
     * Instead, unload all the schemas.  This means we'll also forget about all
     * the installed schemas as well, which means that xml_latest_schema() will
     * fail.  So we need to load the base schemas right now.
     */
    clean_up_extra_schema_files();
    crm_schema_cleanup();
    crm_schema_init();

    crm_info("Fetching extra schema files from cluster");
    pid = fork();

    switch (pid) {
        case -1: {
            rc = errno;
            crm_warn("Could not spawn process to get schema files: %s", pcmk_rc_str(rc));
            break;
        }

        case 0:
            /* child */
            get_schema_files();
            break;

        default:
            /* parent */
            schema_fetch_pid = pid;
            mainloop_child_add_with_flags(pid, 5 * 60 * 1000, "schema-fetch", NULL,
                                          mainloop_leave_pid_group,
                                          get_schema_files_complete);
            break;
    }
}
