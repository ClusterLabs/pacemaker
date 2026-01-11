/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <dirent.h>                 // dirent, scandir
#include <errno.h>                  // errno, EACCES, ENODATA
#include <signal.h>                 // SIGPIPE
#include <stdbool.h>
#include <stddef.h>                 // NULL
#include <stdio.h>                  // rename
#include <stdlib.h>                 // free, mkdtemp
#include <string.h>                 // strerror, strrchr, etc.
#include <sys/stat.h>               // stat, umask, etc.
#include <sys/types.h>              // pid_t
#include <time.h>                   // time_t
#include <unistd.h>                 // _exit, fork

#include <glib.h>                   // g_*, G_*
#include <libxml/tree.h>            // xmlNode
#include <qb/qbdefs.h>              // QB_FALSE, QB_TRUE
#include <qb/qblog.h>               // qb_log_*

#include <crm/cib/internal.h>       // cib_file_*
#include <crm/cib/util.h>           // createEmptyCib
#include <crm/common/internal.h>    // pcmk__assert_asprintf, PCMK__XE_*, etc.
#include <crm/common/logging.h>     // CRM_CHECK
#include <crm/common/mainloop.h>    // mainloop_*
#include <crm/common/results.h>     // pcmk_legacy2rc, pcmk_rc_*
#include <crm/common/util.h>        // pcmk_common_cleanup
#include <crm/common/xml.h>         // PCMK_XA_*, PCMK_XE_*

#include "pacemaker-based.h"

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

    if (based_shutting_down()) {
        pcmk__info("Skipping CIB write during shutdown");
    }

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

        // Remove trigger from main loop
        return 0;
    }

    if (pid > 0) {
        // Parent
        mainloop_child_add(pid, 0, "disk-writer", NULL, write_cib_cb);

        if (blackbox_state == QB_LOG_STATE_ENABLED) {
            qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_TRUE);
        }

        /* Mark job as running and keep trigger. write_cib_cb() will mark it as
         * complete.
         */
        return -1;
    }

    /* Write the CIB. Note that this modifies based_cib, but this child is about
     * to exit. The parent's copy of based_cib won't be affected.
     */
    rc = cib_file_write_with_digest(based_cib, cib_root, "cib.xml");
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
 * \brief Initialize data structures used for CIB manager I/O
 */
void
based_io_init(void)
{
    writes_enabled = !based_stand_alone();
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
 * \brief Free data structures used for CIB manager I/O
 */
void
based_io_cleanup(void)
{
    g_clear_pointer(&write_trigger, mainloop_destroy_trigger);
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

/*!
 * \internal
 * \brief \c scandir() filter for backup CIB files in \c cib_root
 *
 * \param[in] entry  Directory entry
 *
 * \retval 1 if the entry is a regular file whose name begins with \c "cib-" and
 *           does not end with ".sig"
 * \retval 0 otherwise
 */
static int
backup_cib_filter(const struct dirent *entry)
{
    char *path = pcmk__assert_asprintf("%s/%s", cib_root, entry->d_name);
    struct stat sb;
    int rc = stat(path, &sb);

    free(path);

    if (rc != 0) {
        pcmk__warn("Filtering %s/%s during scan for backup CIB: stat() failed: "
                   "%s", cib_root, entry->d_name, strerror(errno));
        return 0;
    }

    return S_ISREG(sb.st_mode)
           && g_str_has_prefix(entry->d_name, "cib-")
           && !g_str_has_suffix(entry->d_name, ".sig");
}

/*!
 * \internal
 * \brief Get a file's last change time (\c ctime)
 *
 * The file is assumed to be a backup CIB file in the \c cib_root directory.
 *
 * \param[in] file  Base name of file
 *
 * \return Last change time of \p file, or 0 on \c stat() failure
 */
static time_t
get_backup_cib_ctime(const char *file)
{
    char *path = pcmk__assert_asprintf("%s/%s", cib_root, file);
    struct stat sb;
    int rc = stat(path, &sb);

    free(path);

    if (rc != 0) {
        pcmk__warn("Failed to stat() %s/%s while sorting backup CIBs: %s",
                   cib_root, file, strerror(errno));
        return 0;
    }

    return sb.st_ctime;
}

/*!
 * \internal
 * \brief Compare directory entries based on their last change times
 *
 * The entries are assumed to be CIB files in the \c cib_root directory.
 *
 * \param[in] entry1  First directory entry to compare
 * \param[in] entry2  Second directory entry to compare
 *
 * \retval -1 if \p entry1 was changed more recently than \p entry2
 * \retval  0 if \p entry1 was last changed at the same timestamp as \p entry2
 * \retval  1 if \p entry1 was changed less recently than \p entry2
 */
static int
compare_backup_cibs(const struct dirent **entry1, const struct dirent **entry2)
{
    time_t ctime1 = get_backup_cib_ctime((*entry1)->d_name);
    time_t ctime2 = get_backup_cib_ctime((*entry2)->d_name);

    if (ctime1 > ctime2) {
        pcmk__trace("%s/%s (%lld) newer than %s/%s (%lld)",
                    cib_root, (*entry1)->d_name, (long long) ctime1,
                    cib_root, (*entry2)->d_name, (long long) ctime2);
        return -1;
    }

    if (ctime1 < ctime2) {
        pcmk__trace("%s/%s (%lld) older than %s/%s (%lld)",
                    cib_root, (*entry1)->d_name, (long long) ctime1,
                    cib_root, (*entry2)->d_name, (long long) ctime2);
        return 1;
    }

    pcmk__trace("%s/%s (%lld) same age as %s/%s (%lld)",
                cib_root, (*entry1)->d_name, (long long) ctime1,
                cib_root, (*entry2)->d_name, (long long) ctime2);
    return 0;
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
    int num_files = scandir(cib_root, &namelist, backup_cib_filter,
                            compare_backup_cibs);

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

    if (!based_stand_alone()) {
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

/*!
 * \internal
 * \brief Read the most recent CIB from a file in \c cib_root
 *
 * This function first tries to read the CIB from a file called \c "cib.xml" in
 * the \c cib_root directory.
 *
 * If that fails or there is a digest mismatch, it tries all the backup CIB
 * files in \c cib_root, in order from most recently changed to least, moving to
 * the next backup file on failure or digest mismatch.
 *
 * If no valid CIB file is found, this function generates an empty CIB.
 *
 * \return The most current CIB XML available, or an empty CIB if none is
 *         available (guaranteed not to be \c NULL)
 *
 * \note The caller is responsible for freeing the return value using
 *       \c pcmk__xml_free().
 */
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

    if (!based_stand_alone()) {
        pcmk__log_xml_trace(cib_xml, "on-disk");
    }

    if (!pcmk__configured_schema_validates(cib_xml)) {
        cib_status = pcmk_rc_schema_validation;
    }

    return cib_xml;
}

/*!
 * \internal
 * \brief Activate new CIB XML
 *
 * This function frees the existing \c based_cib and points it to \p new_cib.
 *
 * \param[in] new_cib  CIB XML to activate (must not be \c NULL or equal to
 *                     \c based_cib)
 * \param[in] to_disk  If \c true and if the CIB status is OK and writes are
 *                     enabled, trigger the new CIB to be written to disk
 * \param[in] op       Operation that triggered the activation (for logging
 *                     only)
 *
 * \return Standard Pacemaker return code
 *
 * \note This function takes ownership of \p new_cib by assigning it to
 *       \c based_cib. The caller should not free it.
 */
int
based_activate_cib(xmlNode *new_cib, bool to_disk, const char *op)
{
    CRM_CHECK((new_cib != NULL) && (new_cib != based_cib), return ENODATA);

    pcmk__xml_free(based_cib);
    based_cib = new_cib;

    if (to_disk && writes_enabled && (cib_status == pcmk_rc_ok)) {
        pcmk__debug("Triggering CIB write for %s op", op);
        mainloop_set_trigger(write_trigger);
    }

    return pcmk_rc_ok;
}
