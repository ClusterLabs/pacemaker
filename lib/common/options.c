/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <crm_internal.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <crm/crm.h>


/*
 * Command-line option handling
 */

static char *crm_short_options = NULL;
static pcmk__cli_option_t *crm_long_options = NULL;
static const char *crm_app_description = NULL;
static const char *crm_app_usage = NULL;

void
pcmk__cli_option_cleanup()
{
    free(crm_short_options);
    crm_short_options = NULL;
}

static struct option *
create_long_opts(pcmk__cli_option_t *long_options)
{
    struct option *long_opts = NULL;

#ifdef HAVE_GETOPT_H
    int index = 0, lpc = 0;

    /*
     * A previous, possibly poor, choice of '?' as the short form of --help
     * means that getopt_long() returns '?' for both --help and for "unknown option"
     *
     * This dummy entry allows us to differentiate between the two in
     * pcmk__next_cli_option() and exit with the correct error code.
     */
    long_opts = pcmk__realloc(long_opts, (index + 1) * sizeof(struct option));
    long_opts[index].name = "__dummmy__";
    long_opts[index].has_arg = 0;
    long_opts[index].flag = 0;
    long_opts[index].val = '_';
    index++;

    // cppcheck seems not to understand the abort-logic in pcmk__realloc
    // cppcheck-suppress memleak
    for (lpc = 0; long_options[lpc].name != NULL; lpc++) {
        if (long_options[lpc].name[0] == '-') {
            continue;
        }

        long_opts = pcmk__realloc(long_opts, (index + 1) * sizeof(struct option));
        /*fprintf(stderr, "Creating %d %s = %c\n", index,
         * long_options[lpc].name, long_options[lpc].val);      */
        long_opts[index].name = long_options[lpc].name;
        long_opts[index].has_arg = long_options[lpc].has_arg;
        long_opts[index].flag = long_options[lpc].flag;
        long_opts[index].val = long_options[lpc].val;
        index++;
    }

    /* Now create the list terminator */
    long_opts = pcmk__realloc(long_opts, (index + 1) * sizeof(struct option));
    long_opts[index].name = NULL;
    long_opts[index].has_arg = 0;
    long_opts[index].flag = 0;
    long_opts[index].val = 0;
#endif

    return long_opts;
}

/*!
 * \internal
 * \brief Define the command-line options a daemon or tool accepts
 *
 * \param[in] short_options  getopt(3)-style short option list
 * \param[in] app_usage      summary of how command is invoked (for help)
 * \param[in] long_options   definition of options accepted
 * \param[in] app_desc       brief command description (for help)
 */
void
pcmk__set_cli_options(const char *short_options, const char *app_usage,
                      pcmk__cli_option_t *long_options, const char *app_desc)
{
    if (short_options) {
        crm_short_options = strdup(short_options);

    } else if (long_options) {
        int lpc = 0;
        int opt_string_len = 0;
        char *local_short_options = NULL;

        for (lpc = 0; long_options[lpc].name != NULL; lpc++) {
            if (long_options[lpc].val && long_options[lpc].val != '-' && long_options[lpc].val < UCHAR_MAX) {
                local_short_options = pcmk__realloc(local_short_options,
                                                    opt_string_len + 4);
                local_short_options[opt_string_len++] = long_options[lpc].val;
                /* getopt(3) says: Two colons mean an option takes an optional arg; */
                if (long_options[lpc].has_arg == optional_argument) {
                    local_short_options[opt_string_len++] = ':';
                }
                if (long_options[lpc].has_arg >= required_argument) {
                    local_short_options[opt_string_len++] = ':';
                }
                local_short_options[opt_string_len] = 0;
            }
        }
        crm_short_options = local_short_options;
        crm_trace("Generated short option string: '%s'", local_short_options);
    }

    if (long_options) {
        crm_long_options = long_options;
    }
    if (app_desc) {
        crm_app_description = app_desc;
    }
    if (app_usage) {
        crm_app_usage = app_usage;
    }
}

int
pcmk__next_cli_option(int argc, char **argv, int *index, const char **longname)
{
#ifdef HAVE_GETOPT_H
    static struct option *long_opts = NULL;

    if (long_opts == NULL && crm_long_options) {
        long_opts = create_long_opts(crm_long_options);
    }

    *index = 0;
    if (long_opts) {
        int flag = getopt_long(argc, argv, crm_short_options, long_opts, index);

        switch (flag) {
            case 0:
                if (long_opts[*index].val) {
                    return long_opts[*index].val;
                } else if (longname) {
                    *longname = long_opts[*index].name;
                } else {
                    crm_notice("Unhandled option --%s", long_opts[*index].name);
                    return flag;
                }
            case -1:           /* End of option processing */
                break;
            case ':':
                crm_trace("Missing argument");
                pcmk__cli_help('?', CRM_EX_USAGE);
                break;
            case '?':
                pcmk__cli_help('?', (*index? CRM_EX_OK : CRM_EX_USAGE));
                break;
        }
        return flag;
    }
#endif

    if (crm_short_options) {
        return getopt(argc, argv, crm_short_options);
    }

    return -1;
}

void
pcmk__cli_help(char cmd, crm_exit_t exit_code)
{
    int i = 0;
    FILE *stream = (exit_code ? stderr : stdout);

    if (cmd == 'v' || cmd == '$') {
        fprintf(stream, "Pacemaker %s\n", PACEMAKER_VERSION);
        fprintf(stream, "Written by Andrew Beekhof\n");
        goto out;
    }

    if (cmd == '!') {
        fprintf(stream, "Pacemaker %s (Build: %s): %s\n", PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
        goto out;
    }

    fprintf(stream, "%s - %s\n", crm_system_name, crm_app_description);

    if (crm_app_usage) {
        fprintf(stream, "Usage: %s %s\n", crm_system_name, crm_app_usage);
    }

    if (crm_long_options) {
        fprintf(stream, "Options:\n");
        for (i = 0; crm_long_options[i].name != NULL; i++) {
            if (crm_long_options[i].flags & pcmk__option_hidden) {

            } else if (crm_long_options[i].flags & pcmk__option_paragraph) {
                fprintf(stream, "%s\n\n", crm_long_options[i].desc);

            } else if (crm_long_options[i].flags & pcmk__option_example) {
                fprintf(stream, "\t#%s\n\n", crm_long_options[i].desc);

            } else if (crm_long_options[i].val == '-' && crm_long_options[i].desc) {
                fprintf(stream, "%s\n", crm_long_options[i].desc);

            } else {
                /* is val printable as char ? */
                if (crm_long_options[i].val && crm_long_options[i].val <= UCHAR_MAX) {
                    fprintf(stream, " -%c,", crm_long_options[i].val);
                } else {
                    fputs("    ", stream);
                }
                fprintf(stream, " --%s%s\t%s\n", crm_long_options[i].name,
                        crm_long_options[i].has_arg == optional_argument ? "[=value]" :
                        crm_long_options[i].has_arg == required_argument ? "=value" : "",
                        crm_long_options[i].desc ? crm_long_options[i].desc : "");
            }
        }

    } else if (crm_short_options) {
        fprintf(stream, "Usage: %s - %s\n", crm_system_name, crm_app_description);
        for (i = 0; crm_short_options[i] != 0; i++) {
            int has_arg = no_argument /* 0 */;

            if (crm_short_options[i + 1] == ':') {
                if (crm_short_options[i + 2] == ':')
                    has_arg = optional_argument /* 2 */;
                else
                    has_arg = required_argument /* 1 */;
            }

            fprintf(stream, " -%c %s\n", crm_short_options[i],
                    has_arg == optional_argument ? "[value]" :
                    has_arg == required_argument ? "{value}" : "");
            i += has_arg;
        }
    }

    fprintf(stream, "\nReport bugs to %s\n", PACKAGE_BUGREPORT);

  out:
    crm_exit(exit_code);
    while(1); // above does not return
}


/*
 * Environment variable option handling
 */

/*!
 * \internal
 * \brief Get the value of a Pacemaker environment variable option
 *
 * If an environment variable option is set, with either a PCMK_ or (for
 * backward compatibility) HA_ prefix, log and return the value.
 *
 * \param[in] option  Environment variable name (without prefix)
 *
 * \return Value of environment variable option
 */
const char *
pcmk__env_option(const char *option)
{
    char env_name[NAME_MAX];
    const char *value = NULL;

    snprintf(env_name, NAME_MAX, "PCMK_%s", option);
    value = getenv(env_name);
    if (value != NULL) {
        crm_trace("Found %s = %s", env_name, value);
        return value;
    }

    snprintf(env_name, NAME_MAX, "HA_%s", option);
    value = getenv(env_name);
    if (value != NULL) {
        crm_trace("Found %s = %s", env_name, value);
        return value;
    }

    crm_trace("Nothing found for %s", option);
    return NULL;
}

/*!
 * \brief Set or unset a Pacemaker environment variable option
 *
 * Set an environment variable option with both a PCMK_ and (for
 * backward compatibility) HA_ prefix.
 *
 * \param[in] option  Environment variable name (without prefix)
 * \param[in] value   New value (or NULL to unset)
 */
void
pcmk__set_env_option(const char *option, const char *value)
{
    char env_name[NAME_MAX];

    snprintf(env_name, NAME_MAX, "PCMK_%s", option);
    if (value) {
        crm_trace("Setting %s to %s", env_name, value);
        setenv(env_name, value, 1);
    } else {
        crm_trace("Unsetting %s", env_name);
        unsetenv(env_name);
    }

    snprintf(env_name, NAME_MAX, "HA_%s", option);
    if (value) {
        crm_trace("Setting %s to %s", env_name, value);
        setenv(env_name, value, 1);
    } else {
        crm_trace("Unsetting %s", env_name);
        unsetenv(env_name);
    }
}

/*!
 * \internal
 * \brief Check whether Pacemaker environment variable option is enabled
 *
 * Given a Pacemaker environment variable option that can either be boolean
 * or a list of daemon names, return true if the option is enabled for a given
 * daemon.
 *
 * \param[in] daemon   Daemon name
 * \param[in] option   Pacemaker environment variable name
 *
 * \return true if variable is enabled for daemon, otherwise false
 */
bool
pcmk__env_option_enabled(const char *daemon, const char *option)
{
    const char *value = pcmk__env_option(option);

    return (value != NULL) && (crm_is_true(value) || strstr(value, daemon));
}


/*
 * Cluster option handling
 */

bool
pcmk__valid_interval_spec(const char *value)
{
    (void) crm_parse_interval_spec(value);
    return errno == 0;
}

bool
pcmk__valid_boolean(const char *value)
{
    int tmp;

    return crm_str_to_boolean(value, &tmp) == 1;
}

bool
pcmk__valid_number(const char *value)
{
    if (value == NULL) {
        return false;

    } else if (pcmk_str_is_minus_infinity(value) ||
               pcmk_str_is_infinity(value)) {
        return true;
    }

    return pcmk__scan_ll(value, NULL, 0LL) == pcmk_rc_ok;
}

bool
pcmk__valid_positive_number(const char *value)
{
    long long num = 0LL;

    return pcmk_str_is_infinity(value)
           || ((pcmk__scan_ll(value, &num, 0LL) == pcmk_rc_ok) && (num > 0));
}

bool
pcmk__valid_quorum(const char *value)
{
    return pcmk__strcase_any_of(value, "stop", "freeze", "ignore", "demote", "suicide", NULL);
}

bool
pcmk__valid_script(const char *value)
{
    struct stat st;

    if (pcmk__str_eq(value, "/dev/null", pcmk__str_casei)) {
        return true;
    }

    if (stat(value, &st) != 0) {
        crm_err("Script %s does not exist", value);
        return false;
    }

    if (S_ISREG(st.st_mode) == 0) {
        crm_err("Script %s is not a regular file", value);
        return false;
    }

    if ((st.st_mode & (S_IXUSR | S_IXGRP)) == 0) {
        crm_err("Script %s is not executable", value);
        return false;
    }

    return true;
}

bool
pcmk__valid_percentage(const char *value)
{
    char *end = NULL;
    long number = strtol(value, &end, 10);

    if (end && (end[0] != '%')) {
        return false;
    }
    return number >= 0;
}

/*!
 * \internal
 * \brief Check a table of configured options for a particular option
 *
 * \param[in] options    Name/value pairs for configured options
 * \param[in] validate   If not NULL, validator function for option value
 * \param[in] name       Option name to look for
 * \param[in] old_name   Alternative option name to look for
 * \param[in] def_value  Default to use if option not configured
 *
 * \return Option value (from supplied options table or default value)
 */
static const char *
cluster_option_value(GHashTable *options, bool (*validate)(const char *),
                     const char *name, const char *old_name,
                     const char *def_value)
{
    const char *value = NULL;
    char *new_value = NULL;

    CRM_ASSERT(name != NULL);

    if (options) {
        value = g_hash_table_lookup(options, name);

        if ((value == NULL) && old_name) {
            value = g_hash_table_lookup(options, old_name);
            if (value != NULL) {
                pcmk__config_warn("Support for legacy name '%s' for cluster "
                                  "option '%s' is deprecated and will be "
                                  "removed in a future release",
                                  old_name, name);

                // Inserting copy with current name ensures we only warn once
                new_value = strdup(value);
                g_hash_table_insert(options, strdup(name), new_value);
                value = new_value;
            }
        }

        if (value && validate && (validate(value) == FALSE)) {
            pcmk__config_err("Using default value for cluster option '%s' "
                             "because '%s' is invalid", name, value);
            value = NULL;
        }

        if (value) {
            return value;
        }
    }

    // No value found, use default
    value = def_value;

    if (value == NULL) {
        crm_trace("No value or default provided for cluster option '%s'",
                  name);
        return NULL;
    }

    if (validate) {
        CRM_CHECK(validate(value) != FALSE,
                  crm_err("Bug: default value for cluster option '%s' is invalid", name);
                  return NULL);
    }

    crm_trace("Using default value '%s' for cluster option '%s'",
              value, name);
    if (options) {
        new_value = strdup(value);
        g_hash_table_insert(options, strdup(name), new_value);
        value = new_value;
    }
    return value;
}

/*!
 * \internal
 * \brief Get the value of a cluster option
 *
 * \param[in] options      Name/value pairs for configured options
 * \param[in] option_list  Possible cluster options
 * \param[in] name         (Primary) option name to look for
 *
 * \return Option value
 */
const char *
pcmk__cluster_option(GHashTable *options, pcmk__cluster_option_t *option_list,
                     int len, const char *name)
{
    const char *value = NULL;

    for (int lpc = 0; lpc < len; lpc++) {
        if (pcmk__str_eq(name, option_list[lpc].name, pcmk__str_casei)) {
            value = cluster_option_value(options, option_list[lpc].is_valid,
                                         option_list[lpc].name,
                                         option_list[lpc].alt_name,
                                         option_list[lpc].default_value);
            return value;
        }
    }
    CRM_CHECK(FALSE, crm_err("Bug: looking for unknown option '%s'", name));
    return NULL;
}

char *
pcmk__format_option_metadata(const char *name, const char *desc_short,
                             const char *desc_long,
                             pcmk__cluster_option_t *option_list, int len)
{
    char *locale = NULL;
    char *escaped_long = NULL;
    char *escaped_short = NULL;
    char *retval;
    /* big enough to hold "pacemaker-schedulerd metadata" output */
    GString *s = g_string_sized_new(13000);
    int lpc = 0;

    escaped_long = crm_xml_escape(desc_long);
    escaped_short = crm_xml_escape(desc_short);

    g_string_append_printf(s, "<?xml version=\"1.0\"?>"
                              "<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
                              "<resource-agent name=\"%s\">\n"
                              "  <version>%s</version>\n"
                              "  <longdesc lang=\"en\">%s</longdesc>\n"
                              "  <shortdesc lang=\"en\">%s</shortdesc>\n"
                              "  <parameters>\n",
                              name, PCMK_OCF_VERSION, escaped_long, escaped_short);
    free(escaped_long);
    free(escaped_short);

    for (lpc = 0; lpc < len; lpc++) {
        if ((option_list[lpc].description_long == NULL)
            && (option_list[lpc].description_short == NULL)) {
            continue;
        }

        g_string_append_printf(s, "    <parameter name=\"%s\">\n",
                                  option_list[lpc].name);

        escaped_long = crm_xml_escape(option_list[lpc].description_long?
                                         option_list[lpc].description_long :
                                          option_list[lpc].description_short);
        escaped_short = crm_xml_escape(option_list[lpc].description_short);

        g_string_append_printf(s,
                                  "      <longdesc lang=\"en\">%s%s%s</longdesc>\n"
                                  "      <shortdesc lang=\"en\">%s</shortdesc>\n",
                                  escaped_long,
                                  (option_list[lpc].values? "  Allowed values: " : ""),
                                  (option_list[lpc].values? option_list[lpc].values : ""),
                                  escaped_short);

#ifdef ENABLE_NLS
        escaped_long = crm_xml_escape(option_list[lpc].description_long?
                                         _(option_list[lpc].description_long) :
                                          _(option_list[lpc].description_short));
        escaped_short = crm_xml_escape(_(option_list[lpc].description_short));

	locale=strtok(setlocale(LC_ALL,NULL),"_");
	g_string_append_printf(s,
                                  "      <longdesc lang=\"%s\">%s%s%s</longdesc>\n"
                                  "      <shortdesc lang=\"%s\">%s</shortdesc>\n",
                                  locale,
				  escaped_long,
                                  (option_list[lpc].values? "  Allowed values: " : ""),
                                  (option_list[lpc].values? option_list[lpc].values : ""),
                                  locale,
				  escaped_short);
#endif
	free(escaped_long);
        free(escaped_short);

        if (option_list[lpc].values && !strcmp(option_list[lpc].type, "select")) {
            char *str = strdup(option_list[lpc].values);
            char delim[] = ", ";
            char *ptr = strtok(str, delim);

            g_string_append_printf(s, "      <content type=\"%s\" default=\"%s\">\n",
                                   option_list[lpc].type,
                                   option_list[lpc].default_value);

            while (ptr != NULL) {
                g_string_append_printf(s, "        <option value=\"%s\" />\n", ptr);
                ptr = strtok(NULL, delim);
            }

            g_string_append_printf(s, "      </content>\n");
            free(str);

        } else {
            g_string_append_printf(s, "      <content type=\"%s\" default=\"%s\"/>\n",
                                   option_list[lpc].type,
                                   option_list[lpc].default_value
            );
        }

        g_string_append_printf(s, "    </parameter>\n");
    }
    g_string_append_printf(s, "  </parameters>\n</resource-agent>\n");

    retval = s->str;
    g_string_free(s, FALSE);
    return retval;
}

void
pcmk__validate_cluster_options(GHashTable *options,
                               pcmk__cluster_option_t *option_list, int len)
{
    for (int lpc = 0; lpc < len; lpc++) {
        cluster_option_value(options, option_list[lpc].is_valid,
                             option_list[lpc].name,
                             option_list[lpc].alt_name,
                             option_list[lpc].default_value);
    }
}
