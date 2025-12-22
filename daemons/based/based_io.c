/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/crm.h>

#include <crm/cib.h>
#include <crm/common/util.h>
#include <crm/common/xml.h>
#include <crm/cib/internal.h>
#include <crm/cluster.h>

#include <pacemaker-based.h>

static bool writes_enabled = true;
static crm_trigger_t *write_trigger = NULL;

/*!
 * \internal
 * \brief Process the exit status of a child forked from \c write_cib_async()
 *
 * \param[in] child      Mainloop child data
 * \param[in] core       If set to 1, the child process dumped core
 * \param[in] signo      Signal that the child process exited with
 * \param[in] exit_code  Child process's exit code
 */
static void
write_cib_cb(mainloop_child_t *child, int core, int signo, int exit_code)
{
    const char *error = "Could not write CIB to disk";

    if ((exit_code != 0) && writes_enabled) {
        writes_enabled = false;
        error = "Disabling CIB disk writes after failure";
    }

    if ((signo == 0) && (exit_code == 0)) {
        pcmk__trace("Disk write [%lld] succeeded", (long long) child->pid);

    } else if (signo == 0) {
        pcmk__err("%s: process %lld exited with code %d", error,
                  (long long) child->pid, exit_code);

    } else {
        pcmk__err("%s: process %lld terminated with signal %d (%s)%s",
                  error, (long long) child->pid, signo, strsignal(signo),
                  ((core != 0)? " and dumped core" : ""));
    }

    mainloop_trigger_complete(write_trigger);
}

/*!
 * \internal
 * \brief Write the CIB to disk in a forked child
 *
 * This avoids blocking in the parent. The child writes synchronously. The
 * parent tracks the child via the mainloop and runs a callback when the child
 * exits.
 *
 * \param[in] user_data  Ignored
 */
static int
write_cib_async(gpointer user_data)
{
    int rc = pcmk_rc_ok;
    pid_t pid = 0;
    int blackbox_state = qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_STATE_GET, 0);

    /* Disable blackbox logging before the fork to avoid two processes writing
     * to the same shared memory. The disable should not be done in the child,
     * because this would close shared memory files in the parent.
     *
     * @TODO How? What is meant by this last sentence?
     */
    qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_FALSE);

    pid = fork();
    if (pid < 0) {
        pcmk__err("Disabling disk writes after fork failure: %s",
                  strerror(errno));
        writes_enabled = false;
        return G_SOURCE_REMOVE;
    }

    if (pid > 0) {
        // Parent
        mainloop_child_add(pid, 0, "disk-writer", NULL, write_cib_cb);

        if (blackbox_state == QB_LOG_STATE_ENABLED) {
            qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_TRUE);
        }

        return G_SOURCE_CONTINUE;
    }

    /* Write the CIB. Note that this modifies the_cib, but this child is about
     * to exit. The parent's copy of the_cib won't be affected.
     */
    rc = cib_file_write_with_digest(the_cib, cib_root, "cib.xml");
    rc = pcmk_legacy2rc(rc);

    pcmk_common_cleanup();

    /* A nonzero exit code will cause further writes to be disabled. Use _exit()
     * because exit() could affect the parent adversely.
     *
     * @TODO Investigate whether _exit() instead of exit() is really necessary.
     * This goes back to commit 58cb43dc, which states that exit() may close
     * things it shoudn't close. There is no explanation of what these things
     * might be. The exit(2) man page states that exit() calls atexit/on_exit
     * handlers and flushes open stdio streams. The exit(3) man page states that
     * file created with tmpfile() are removed. But neither Pacemaker nor libqb
     * uses atexit or on_exit, and it's not clear why we'd be worried about
     * stdio streams.
     */
    switch (rc) {
        case pcmk_rc_ok:
            _exit(CRM_EX_OK);

        case pcmk_rc_cib_modified:
            _exit(CRM_EX_DIGEST);

        case pcmk_rc_cib_backup:
        case pcmk_rc_cib_save:
            _exit(CRM_EX_CANTCREAT);

        default:
            _exit(CRM_EX_ERROR);
    }
}

/*!
 * \internal
 * \brief Enable CIB writes to disk (signal handler)
 *
 * \param[in] nsig  Ignored
 */
void
based_enable_writes(int nsig)
{
    pcmk__info("(Re)enabling disk writes");
    writes_enabled = true;
}

/*!
 * \internal
 * \brief Initialize data structures for \c pacemaker-based I/O
 */
void
based_io_init(void)
{
    writes_enabled = !stand_alone;
    if (writes_enabled
        && pcmk__env_option_enabled(PCMK__SERVER_BASED,
                                    PCMK__ENV_VALGRIND_ENABLED)) {

        writes_enabled = false;
        pcmk__err("*** Disabling disk writes to avoid confusing Valgrind ***");
    }

    /* @TODO Should we be setting this up if we've explicitly disabled writes
     * already?
     */
    mainloop_add_signal(SIGPIPE, based_enable_writes);

    write_trigger = mainloop_add_trigger(G_PRIORITY_LOW, write_cib_async, NULL);
}

/*!
 * \internal
 * \brief Rename a CIB or digest file after digest mismatch
 *
 * This is just a wrapper for logging an error. The caller should disable writes
 * on error.
 *
 * \param[in] old_path  Original file path
 * \param[in] new_path  New file path
 *
 * \return Standard Pacemaker return code
 */
static int
rename_one(const char *old_path, const char *new_path)
{
    int rc = rename(old_path, new_path);

    if (rc == 0) {
        return pcmk_rc_ok;
    }

    rc = errno;
    pcmk__err("Failed to rename %s to %s after digest mismatch: %s. Disabling "
              "disk writes.", old_path, new_path, strerror(rc));
    return rc;
}

#define CIBFILE "cib.xml"

/*!
 * \internal
 * \brief Archive the current CIB file in \c cib_root with its saved digest file
 *
 * When a CIB file's calculated digest doesn't match its saved one, we archive
 * both the CIB file and its digest (".sig") file. This way the contents can be
 * inspected for troubleshooting purposes.
 *
 * A subdirectory with a unique name is created in \c cib_root, using the
 * \c mkdtemp() template \c "cib.auto.XXXXXX". Then \c CIB_FILE and
 * <tt>CIB_FILE ".sig"</tt> are moved to that directory.
 *
 * \param[in] old_cibfile_path  Original path of CIB file
 * \param[in] old_sigfile_path  Original path of digest file
 */
static void
archive_on_digest_mismatch(const char *old_cibfile_path,
                           const char *old_sigfile_path)
{
    char *new_dir = pcmk__assert_asprintf("%s/cib.auto.XXXXXX", cib_root);
    char *new_cibfile_path = NULL;
    char *new_sigfile_path = NULL;

    umask(S_IWGRP | S_IWOTH | S_IROTH);

    if (mkdtemp(new_dir) == NULL) {
        pcmk__err("Failed to create directory to archive %s and %s after "
                  "digest mismatch: %s. Disabling disk writes.",
                  old_cibfile_path, old_sigfile_path, strerror(errno));
        writes_enabled = false;
        goto done;
    }

    new_cibfile_path = pcmk__assert_asprintf("%s/%s", new_dir, CIBFILE);
    new_sigfile_path = pcmk__assert_asprintf("%s.sig", new_cibfile_path);

    if ((rename_one(old_cibfile_path, new_cibfile_path) != pcmk_rc_ok)
        || (rename_one(old_sigfile_path, new_sigfile_path) != pcmk_rc_ok)) {

        writes_enabled = false;
        goto done;
    }

    pcmk__err("Archived %s and %s in %s after digest mismatch",
              old_cibfile_path, old_sigfile_path, new_dir);

done:
    free(new_dir);
    free(new_cibfile_path);
    free(new_sigfile_path);
}

/*!
 * \internal
 * \brief Read CIB XML from \c CIBFILE in the \c cib_root directory
 *
 * \return CIB XML parsed from \c CIBFILE in \c cib_root , or \c NULL if the
 *         file was not found or if parsing failed
 *
 * \note The caller is responsible for freeing the return value using
 *       \c pcmk__xml_free().
 */
static xmlNode *
read_current_cib(void)
{
    char *cibfile_path = pcmk__assert_asprintf("%s/%s", cib_root, CIBFILE);
    char *sigfile_path = pcmk__assert_asprintf("%s.sig", cibfile_path);
    const char *sigfile = strrchr(sigfile_path, '/') + 1;

    xmlNode *cib_xml = NULL;
    int rc = pcmk_rc_ok;

    if (!pcmk__daemon_can_write(cib_root, CIBFILE)
        || !pcmk__daemon_can_write(cib_root, sigfile)) {

        cib_status = EACCES;
        goto done;
    }

    cib_status = pcmk_rc_ok;

    rc = cib_file_read_and_verify(cibfile_path, sigfile_path, &cib_xml);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        pcmk__info("Loaded CIB from %s (with digest %s)", cibfile_path,
                   sigfile_path);
        goto done;
    }

    pcmk__warn("Continuing but NOT using CIB from %s (with digest %s): %s",
               cibfile_path, sigfile_path, pcmk_rc_str(rc));

    if (rc == pcmk_rc_cib_modified) {
        // Archive the original files so the contents are not lost
        archive_on_digest_mismatch(cibfile_path, sigfile_path);
    }

done:
    free(cibfile_path);
    free(sigfile_path);
    return cib_xml;
}

static int cib_archive_filter(const struct dirent * a)
{
    int rc = 0;
    // Looking for regular files starting with "cib-" and not ending in .sig
    struct stat s;
    char *a_path = pcmk__assert_asprintf("%s/%s", cib_root, a->d_name);

    if(stat(a_path, &s) != 0) {
        rc = errno;
        pcmk__trace("%s - stat failed: %s (%d)", a->d_name, pcmk_rc_str(rc),
                    rc);
        rc = 0;

    } else if (!S_ISREG(s.st_mode)) {
        pcmk__trace("%s - wrong type (%#o)", a->d_name,
                    (unsigned int) (s.st_mode & S_IFMT));

    } else if (!g_str_has_prefix(a->d_name, "cib-")) {
        pcmk__trace("%s - wrong prefix", a->d_name);

    } else if (g_str_has_suffix(a->d_name, ".sig")) {
        pcmk__trace("%s - wrong suffix", a->d_name);

    } else {
        pcmk__debug("%s - candidate", a->d_name);
        rc = 1;
    }

    free(a_path);
    return rc;
}

static int cib_archive_sort(const struct dirent ** a, const struct dirent **b)
{
    /* Order by creation date - most recently created file first */
    int rc = 0;
    struct stat buf;

    time_t a_age = 0;
    time_t b_age = 0;

    char *a_path = pcmk__assert_asprintf("%s/%s", cib_root, a[0]->d_name);
    char *b_path = pcmk__assert_asprintf("%s/%s", cib_root, b[0]->d_name);

    if(stat(a_path, &buf) == 0) {
        a_age = buf.st_ctime;
    }
    if(stat(b_path, &buf) == 0) {
        b_age = buf.st_ctime;
    }

    free(a_path);
    free(b_path);

    if (a_age > b_age) {
        // a newer than b
        rc = -1;
    } else if (a_age < b_age) {
        // a older than b
        rc = 1;
    }

    pcmk__trace("%s (%lu) vs. %s (%lu) : %d",
	a[0]->d_name, (unsigned long)a_age,
	b[0]->d_name, (unsigned long)b_age, rc);
    return rc;
}

/*!
 * \internal
 * \brief Read CIB XML from the last valid backup file in \c cib_root
 *
 * \return CIB XML parsed from the last valid backup file, or \c NULL if none
 *         was found
 */
static xmlNode *
read_backup_cib(void)
{
    xmlNode *cib_xml = NULL;
    struct dirent **namelist = NULL;
    int num_files = scandir(cib_root, &namelist, cib_archive_filter,
                            cib_archive_sort);

    if (num_files < 0) {
        pcmk__err("Could not check for CIB backups in %s: %s", cib_root,
                  pcmk_rc_str(errno));
        goto done;
    }

    for (int i = 0; i < num_files; i++) {
        const char *cibfile = namelist[i]->d_name;
        char *cibfile_path = pcmk__assert_asprintf("%s/%s", cib_root, cibfile);
        char *sigfile_path = pcmk__assert_asprintf("%s.sig", cibfile_path);

        int rc = cib_file_read_and_verify(cibfile_path, sigfile_path, &cib_xml);

        rc = pcmk_legacy2rc(rc);

        if (rc == pcmk_rc_ok) {
            pcmk__notice("Loaded CIB from last valid backup %s (with digest "
                         "%s)", cibfile_path, sigfile_path);
        } else {
            pcmk__warn("Not using next most recent CIB backup from %s (with "
                       "digest %s): %s", cibfile_path, sigfile_path,
                       pcmk_rc_str(rc));
        }

        free(cibfile_path);
        free(sigfile_path);

        if (rc == pcmk_rc_ok) {
            break;
        }
    }

done:
    for (int i = 0; i < num_files; i++) {
        free(namelist[i]);
    }
    free(namelist);

    return cib_xml;
}

/*!
 * \internal
 * \brief Set the CIB XML's \c PCMK_XE_STATUS element to empty if appropriate
 *
 * Delete the current \c PCMK_XE_STATUS element if not running in stand-alone
 * mode. Then create an empty \c PCMK_XE_STATUS child if either of the following
 * is true:
 * * not running in stand-alone mode
 * * running in stand-alone mode with no \c PCMK_XE_STATUS element
 *
 * \param[in,out] cib_xml  CIB XML
 */
static void
set_empty_status(xmlNode *cib_xml)
{
    xmlNode *status = pcmk__xe_first_child(cib_xml, PCMK_XE_STATUS, NULL, NULL);

    if (!stand_alone) {
        g_clear_pointer(&status, pcmk__xml_free);
    }

    if (status == NULL) {
        pcmk__xe_create(cib_xml, PCMK_XE_STATUS);
    }
}

/*!
 * \internal
 * \brief Set the given CIB version attribute to 0 if it's not already set
 *
 * \param[in,out] cib_xml       CIB XML
 * \param[in]     version_attr  Version attribute
 */
static void
set_default_if_unset(xmlNode *cib_xml, const char *version_attr)
{
    if (pcmk__xe_get(cib_xml, version_attr) != NULL) {
        return;
    }

    pcmk__warn("Defaulting missing %s to 0, but cluster may get confused about "
               "which node's configuration is most recent", version_attr);
    pcmk__xe_set_int(cib_xml, version_attr, 0);
}

xmlNode *
based_read_cib(void)
{
    static const char *version_attrs[] = {
        PCMK_XA_ADMIN_EPOCH,
        PCMK_XA_EPOCH,
        PCMK_XA_NUM_UPDATES,
    };

    xmlNode *cib_xml = read_current_cib();

    if (cib_xml == NULL) {
        cib_xml = read_backup_cib();
    }

    if (cib_xml == NULL) {
        cib_xml = createEmptyCib(0);
        pcmk__warn("Continuing with an empty configuration");
    }

    set_empty_status(cib_xml);

    /* Default the three version attributes to 0 if unset. The schema requires
     * them to be set, so:
     * * It's not possible for them to be unset if schema validation was enabled
     *   when the CIB file was generated, or if it was generated by Pacemaker
     *   and then unmodified.
     * * We need to set these defaults before schema validation happens.
     */
    for (int i = 0; i < PCMK__NELEM(version_attrs); i++) {
        set_default_if_unset(cib_xml, version_attrs[i]);
    }

    // The DC should set appropriate value for PCMK_XA_DC_UUID
    pcmk__xe_remove_attr(cib_xml, PCMK_XA_DC_UUID);

    if (!stand_alone) {
        pcmk__log_xml_trace(cib_xml, "on-disk");
    }

    if (!pcmk__configured_schema_validates(cib_xml)) {
        cib_status = pcmk_rc_schema_validation;
    }

    return cib_xml;
}

void
uninitializeCib(void)
{
    xmlNode *tmp_cib = the_cib;

    if (tmp_cib == NULL) {
        return;
    }

    the_cib = NULL;
    pcmk__xml_free(tmp_cib);
}

/*
 * This method will free the old CIB pointer on success and the new one
 * on failure.
 */
int
activateCibXml(xmlNode *new_cib, bool to_disk, const char *op)
{
    if (new_cib) {
        xmlNode *saved_cib = the_cib;

        pcmk__assert(new_cib != saved_cib);
        the_cib = new_cib;
        pcmk__xml_free(saved_cib);
        if (to_disk && writes_enabled && (cib_status == pcmk_rc_ok)) {
            pcmk__debug("Triggering CIB write for %s op", op);
            mainloop_set_trigger(write_trigger);
        }
        return pcmk_ok;
    }

    pcmk__err("Ignoring invalid CIB");
    if (the_cib) {
        pcmk__warn("Reverting to last known CIB");
    } else {
        pcmk__crit("Could not write out new CIB and no saved version to revert "
                   "to");
    }
    return -ENODATA;
}
