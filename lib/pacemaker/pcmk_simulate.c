/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/pengine/pe_types.h>
#include <pacemaker-internal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

void
pcmk__profile_file(const char *xml_file, long long repeat, pe_working_set_t *data_set, char *use_date)
{
    pcmk__output_t *out = data_set->priv;
    xmlNode *cib_object = NULL;
    clock_t start = 0;
    clock_t end;

    CRM_ASSERT(out != NULL);

    cib_object = filename2xml(xml_file);
    start = clock();

    if (get_object_root(XML_CIB_TAG_STATUS, cib_object) == NULL) {
        create_xml_node(cib_object, XML_CIB_TAG_STATUS);
    }

    if (cli_config_update(&cib_object, NULL, FALSE) == FALSE) {
        free_xml(cib_object);
        return;
    }

    if (validate_xml(cib_object, NULL, FALSE) != TRUE) {
        free_xml(cib_object);
        return;
    }

    for (int i = 0; i < repeat; ++i) {
        xmlNode *input = (repeat == 1)? cib_object : copy_xml(cib_object);

        data_set->input = input;
        pcmk__set_effective_date(data_set, false, use_date);
        pcmk__schedule_actions(data_set, input, NULL);
        pe_reset_working_set(data_set);
    }

    end = clock();
    out->message(out, "profile", xml_file, start, end);
}

void
pcmk__profile_dir(const char *dir, long long repeat, pe_working_set_t *data_set, char *use_date)
{
    pcmk__output_t *out = data_set->priv;
    struct dirent **namelist;

    int file_num = scandir(dir, &namelist, 0, alphasort);

    CRM_ASSERT(out != NULL);

    if (file_num > 0) {
        struct stat prop;
        char buffer[FILENAME_MAX];

        out->begin_list(out, NULL, NULL, "Timings");

        while (file_num--) {
            if ('.' == namelist[file_num]->d_name[0]) {
                free(namelist[file_num]);
                continue;

            } else if (!pcmk__ends_with_ext(namelist[file_num]->d_name,
                                            ".xml")) {
                free(namelist[file_num]);
                continue;
            }
            snprintf(buffer, sizeof(buffer), "%s/%s", dir, namelist[file_num]->d_name);
            if (stat(buffer, &prop) == 0 && S_ISREG(prop.st_mode)) {
                pcmk__profile_file(buffer, repeat, data_set, use_date);
            }
            free(namelist[file_num]);
        }
        free(namelist);

        out->end_list(out);
    }
}

void
pcmk__set_effective_date(pe_working_set_t *data_set, bool print_original, char *use_date)
{
    pcmk__output_t *out = data_set->priv;
    time_t original_date = 0;

    CRM_ASSERT(out != NULL);

    crm_element_value_epoch(data_set->input, "execution-date", &original_date);

    if (use_date) {
        data_set->now = crm_time_new(use_date);
        out->info(out, "Setting effective cluster time: %s", use_date);
        crm_time_log(LOG_NOTICE, "Pretending 'now' is", data_set->now,
                     crm_time_log_date | crm_time_log_timeofday);

    } else if (original_date) {

        data_set->now = crm_time_new(NULL);
        crm_time_set_timet(data_set->now, &original_date);

        if (print_original) {
            char *when = crm_time_as_string(data_set->now,
                            crm_time_log_date|crm_time_log_timeofday);

            out->info(out, "Using the original execution date of: %s", when);
            free(when);
        }
    }
}
