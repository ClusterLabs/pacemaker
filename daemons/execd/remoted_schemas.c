/*
 * Copyright 2023-2026 the Pacemaker project contributors
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
#include <crm/common/mainloop.h>
#include <crm/common/xml.h>

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
        pcmk__err("Could not remove %s: %s", pathname, pcmk_rc_str(rc));
        return -1;
    }

    return 0;
}

static void
clean_up_extra_schema_files(void)
{
    const char *remote_schema_dir = pcmk__remote_schema_dir();
    int rc;

    /* Try to create the remote schema directory first. */
    rc = mkdir(remote_schema_dir, 0755);

    if (rc == 0) {
        /* Success. */
        return;
    }

    if (errno == EEXIST) {
        /* The path already exists.  Assume it's a directory and try to clear
         * it out so we can download new schema files.  If it's not a directory,
         * nftw will fail and set errno.
         */
        rc = nftw(remote_schema_dir, rm_files, 10, FTW_DEPTH|FTW_MOUNT|FTW_PHYS);

        if (rc == 0) {
            /* Success. */
            return;
        }

        if (errno == ENOTDIR) {
            /* Something other than a directory already has that name. */
            pcmk__err("%s already exists but is not a directory",
                      remote_schema_dir);
        } else {
            rc = errno;
            pcmk__err("Could not clear directory %s: %s", remote_schema_dir,
                      pcmk_rc_str(rc));
        }
    } else {
        rc = errno;
        pcmk__err("Could not create directory for schemas: %s",
                  pcmk_rc_str(rc));
    }
}

static void
write_extra_schema_file(xmlNode *xml, void *user_data)
{
    const char *remote_schema_dir = pcmk__remote_schema_dir();
    const char *file = NULL;
    char *path = NULL;
    int rc;

    file = pcmk__xe_get(xml, PCMK_XA_PATH);
    if (file == NULL) {
        pcmk__warn("No destination path given in schema request");
        return;
    }

    path = pcmk__assert_asprintf("%s/%s", remote_schema_dir, file);

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
            pcmk__warn("Could not write schema file %s: %s", path,
                       strerror(errno));
        } else {
            rc = fprintf(stream, "%s", child->content);

            if (rc < 0) {
                pcmk__warn("Could not write schema file %s: %s", path,
                           strerror(errno));
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
        pcmk_common_cleanup();
        _exit(CRM_EX_OSERR);
    }

    rc = cib->cmds->signon(cib, crm_system_name, cib_command);
    rc = pcmk_legacy2rc(rc);
    if (rc != pcmk_rc_ok) {
        pcmk__err("Could not connect to the CIB manager: %s", pcmk_rc_str(rc));
        pcmk_common_cleanup();
        _exit(pcmk_rc2exitc(rc));
    }

    rc = cib->cmds->fetch_schemas(cib, &reply, pcmk__highest_schema_name(),
                                  cib_sync_call);
    if (rc != pcmk_ok) {
        pcmk__err("Could not get schema files: %s", pcmk_strerror(rc));
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
        pcmk__xpath_foreach_result(reply->doc, "//" PCMK__XE_FILE,
                                   write_extra_schema_file, NULL);
    }

    pcmk__xml_free(reply);
    cib__clean_up_connection(&cib);
    pcmk_common_cleanup();
    _exit(pcmk_rc2exitc(rc));
}

/* Load any additional schema files when the child is finished fetching and
 * saving them to disk.
 */
static void
get_schema_files_complete(mainloop_child_t *p, int core, int signo,
                          int exitcode)
{
    const char *errmsg = "Could not load additional schema files";

    if ((signo == 0) && (exitcode == 0)) {
        const char *remote_schema_dir = pcmk__remote_schema_dir();

        /* Don't just call pcmk__schema_init() here because that will load the
         * base schemas again too. Instead just load the things we fetched.
         */
        pcmk__load_schemas_from_dir(remote_schema_dir);
        pcmk__sort_schemas();
        pcmk__info("Fetching extra schema files completed successfully");

    } else {
        if (signo == 0) {
            pcmk__err("%s: process %lld exited %d", errmsg, (long long) p->pid,
                      exitcode);

        } else {
            pcmk__err("%s: process %lld terminated with signal %d (%s)%s",
                      errmsg, (long long) p->pid, signo, strsignal(signo),
                      ((core != 0)? " and dumped core" : ""));
        }

        /* Clean up any incomplete schema data we might have been downloading
         * when the process timed out or crashed. We don't need to do any extra
         * cleanup because we never loaded the extra schemas, and we don't need
         * to call pcmk__schema_init() because that was called in
         * remoted_request_cib_schema_files() before this function.
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
            pcmk__warn("Unable to kill pre-existing schema-fetch process");
            return;
        }

        schema_fetch_pid = 0;
    }

    /* Clean up any extra schema files we downloaded from a previous cluster
     * connection.  After the files are gone, we need to wipe them from
     * known_schemas, but there's no opposite operation for add_schema().
     *
     * Instead, unload all the schemas.  This means we'll also forget about all
     * installed schemas as well, which means that pcmk__highest_schema_name()
     * would fail. So we need to load the base schemas right now.
     */
    clean_up_extra_schema_files();
    pcmk__schema_cleanup();
    pcmk__schema_init();

    pcmk__info("Fetching extra schema files from cluster");
    pid = fork();

    switch (pid) {
        case -1: {
            rc = errno;
            pcmk__warn("Could not spawn process to get schema files: %s",
                       pcmk_rc_str(rc));
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
