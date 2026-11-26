/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/xml.h>

#include <crm/crm.h>

#include <pacemaker-internal.h>

#define SUMMARY "crm_error - display name or description of a Pacemaker error code"

struct {
    gboolean with_name;
    gboolean do_list;
    enum pcmk_result_type result_type; // How to interpret result codes
} options = {
    .result_type = pcmk_result_legacy,
};

static gboolean
result_type_cb(const char *option_name, const char *optarg, void *data,
               GError **error)
{
    if (pcmk__str_any_of(option_name, "--exit", "-X", NULL)) {
        options.result_type = pcmk_result_exitcode;
    } else if (pcmk__str_any_of(option_name, "--rc", "-r", NULL)) {
        options.result_type = pcmk_result_rc;
    }

    return TRUE;
}

static GOptionEntry entries[] = {
    { "name", 'n', 0, G_OPTION_ARG_NONE, &options.with_name,
      "Show error's name with its description (useful for looking for sources "
      "of the error in source code)",
       NULL },
    { "list", 'l', 0, G_OPTION_ARG_NONE, &options.do_list,
      "Show all known errors (enabled by default if no rc is specified)",
      NULL },
    { "exit", 'X', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, result_type_cb,
      "Interpret as exit code rather than legacy function return value",
      NULL },
    { "rc", 'r', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, result_type_cb,
      "Interpret as return code rather than legacy function return value",
      NULL },

    { NULL }
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, "text (default), xml", group,
                                      "[-- <rc> [<rc>...]]");
    pcmk__add_main_args(context, entries);
    return context;
}

int
main(int argc, char **argv)
{
    crm_exit_t exit_code = CRM_EX_OK;
    int rc = pcmk_rc_ok;

    pcmk__output_t *out = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
    GOptionContext *context = build_arg_context(args, &output_group);

    pcmk__register_formats(output_group, NULL);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_error", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s", args->output_ty,
                    pcmk_rc_str(rc));
        goto done;
    }

    if (g_strv_length(processed_args) < 2) {
        // If no result codes were specified, list them all
        options.do_list = TRUE;
    }

    if (args->version) {
        {
            #define ORIG_CIB                                                            \
    "<" PCMK_XE_CIB " " PCMK_XA_ADMIN_EPOCH "=\"0\""                        \
                    " " PCMK_XA_EPOCH "=\"0\""                              \
                    " " PCMK_XA_NUM_UPDATES "=\"0\">"                       \
      "<" PCMK_XE_CONFIGURATION ">"                                         \
        "<" PCMK_XE_CRM_CONFIG "/>"                                         \
        "<" PCMK_XE_NODES "/>"                                              \
        "<" PCMK_XE_RESOURCES "/>"                                          \
        "<" PCMK_XE_CONSTRAINTS "/>"                                        \
      "</" PCMK_XE_CONFIGURATION ">"                                        \
      "<" PCMK_XE_STATUS "/>"                                               \
    "</" PCMK_XE_CIB ">"

            #define BASE_CIB                                                              \
    "<cib crm_feature_set=\"3.19.0\" validate-with=\"pacemaker-3.10\""        \
    "     admin_epoch=\"0\" epoch=\"1\" num_updates=\"0\">"                   \
    "  <configuration>"                                                       \
    "    <crm_config>"                                                        \
    "      <cluster_property_set id=\"cib-bootstrap-options\">"               \
    "        <nvpair id=\"cib-bootstrap-options-stonith-enabled\""            \
    "               name=\"stonith-enabled\" value=\"false\"/>"               \
    "      </cluster_property_set>"                                           \
    "    </crm_config>"                                                       \
    "    <nodes>"                                                             \
    "      <node id=\"1\" uname=\"node1\"/>"                                  \
    "      <node id=\"2\" uname=\"node2\"/>"                                  \
    "    </nodes>"                                                            \
    "    <resources>"                                                         \
    "      <primitive id=\"r1\" class=\"ocf\" provider=\"heartbeat\""         \
    "                 type=\"Dummy\">"                                        \
    "        <operations>"                                                    \
    "          <op id=\"r1-monitor\" name=\"monitor\" interval=\"10s\"/>"     \
    "        </operations>"                                                   \
    "      </primitive>"                                                      \
    "      <primitive id=\"r2\" class=\"ocf\" provider=\"heartbeat\""         \
    "                 type=\"Stateful\"/>"                                    \
    "    </resources>"                                                        \
    "    <constraints>"                                                       \
    "      <rsc_location id=\"loc1\" rsc=\"r1\" node=\"node1\" score=\"100\"/>" \
    "    </constraints>"                                                      \
    "  </configuration>"                                                      \
    "  <status/>"                                                             \
    "</cib>"

            #define CREATE_THEN_DELETE                                                  \
    "<" PCMK_XE_DIFF " " PCMK_XA_FORMAT "=\"2\">"                           \
      "<" PCMK_XE_CHANGE " " PCMK_XA_OPERATION "=\"" PCMK_VALUE_CREATE "\"" \
                        " " PCMK_XA_PATH "=\"/" PCMK_XE_CIB                 \
                            "/" PCMK_XE_CONFIGURATION                       \
                            "/" PCMK_XE_RESOURCES "\""                      \
                        " position=\"0\">"                      \
        "<" PCMK_XE_PRIMITIVE " " PCMK_XA_ID "=\"r\"/>"                     \
      "</" PCMK_XE_CHANGE ">"                                               \
      "<" PCMK_XE_CHANGE " " PCMK_XA_OPERATION "=\"" PCMK_VALUE_DELETE "\"" \
                        " " PCMK_XA_PATH "=\"/" PCMK_XE_CIB                 \
                            "/" PCMK_XE_CONFIGURATION                       \
                            "/" PCMK_XE_RESOURCES "\"/>"                    \
    "</" PCMK_XE_DIFF ">"

        #define PATCHSET_585479762                                          \
            "<diff format=\"2\" digest=\"0123456789abcdef0abcdef0123456789abcdef\">"    \
                "<version>"                                                             \
                    "<source admin_epoch=\"0\" epoch=\"1\" num_updates=\"1\"/>"         \
                "</version>"                                                            \
                "<change operation=\"delete\" path=\"\"/>"                              \
                "/status\" />"                                                          \
            "</diff>"

        #define PATCHSET_585402262                                          \
            "<diff format=\"2\">"   \
                "<version>"         \
                    "KKKKKKKKKKKKKKKKn_epoch=\"0\" epoch=\"1\" num_ustatuspdates=\"6866crm_f\"/>"    \
                "</version>"        \
                    "<change operation=\"create\" path=\"ocib/config@'dri1']/operations/op[@id='r1-monitor']\"><op interval=\"30s\" name=\"monitor\" id=\"r2-monitor\" />%%%%%%%%%%%'%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%    <change-result>"    \
                            "/cib/cjnfiguration   <op id=\"r2-monitor\" name=\"monitor\" interval=\"30s\" />"   \
                        "</change-result>"  \
                    "</change>29"           \
            "</diff>"

        #define PATCHSET_584890034  \
            "<df format=\"2\"><e operation=\"move\" path=\"\" position=\"2\"/></df>"

        #define PATCHSET_583469453  \
            "<diff format=\"2\">" \
  "<version>" \
    "<source admin_epoch=\"0\" epoch=\"1\" num_upd=\"0\"/>" \
    "<target admin_epoch=\"0\" epoch=\"1\" num_updates=\"1\"/>" \
  "</version>" \
  "<change operation=\"delete\" path=\"/cib/configuration/nodes/node[@id='1']\" />" \
  "<change operation=\"create\" path=\"/cib/configuration/constraints\" position=\"1\">t    <rsc_location id=\"loc2\" rsc=\"r2\" node=\"node2\" score=\"-IitioITY\"/>" \
  "</change><change operation=\"create\" path=\"/cib/configuration/constraints\" position=\"1\">t    <rsc_location id=\"loc2\" rsc=\"r2\" node=\"node2\" score=\"-IitioITY\"/>" \
  "</change>" \
  "<change operation=\"modify\" path=\"Acib/configuration/crm_config/cluster_property_set[@id='cib-bootstrap-options']\">" \
    "<change-list>" \
      "<change-attr name=\"id\" operatfon=\"set\" value=\"cib-bootstrap-options\"/>" \
    "</change-list>" \
    "<change-result>" \
      "<cluster_property_set id=\"cib-bootstge-list> " \
  "\" score=\"6\"/>" \
    "</change-result>" \
  "</change>" \
"</diff>"

            #define PATCHSET_586237603 \
            "<diff format=\"2\">" \
  "<version>" \
    "<source admin_hiddeepoch=\"0\" epoch=\"1\" num_updates=\"0\"/>" \
    "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=YYYYYYYYYYYYYYYYYYY<trgaet admin_epoch=\"6\" epoch=\"1\" num_updates=\"1\"/>" \
 "z </version>" \
 "`<change operation=\"modify\" path=\"/cib/configurationr/esouxmlrces/primitive[@id='r1']/operations/op[@id='r1-monitor']\">" \
"change-result>" \
  "</change><change operation=\"modify\" path=\"/cib/configuration/resources/primi\" patth=\"/cib/configuration/resources/primitive[@id='r1']/operations/op[@id='r1-monitor']\">" \
"change-result>" \
  "</change><change operation=\"mqdify\" path=\"/cib/configuration/resourcns/primitive[@id='r1']/operations/op[@id='r1-monitor']\">" \
"change-result>" \
  "</change><change operation=\"modify\" path=\"/cib/configuration/resources/primitive[@id='r1']/operations/op[@id='r1-monitor']\">" \
"change-result>" \
  "</change><change operation=\"modify\" path=\"/cib/bonfiguration/resources/primitive[@id='r1']/operations/op[@id='r1-monitor']\">" \
"change-result>" \
  "</change><change operation=\"codefy\" path=\"/cib/configuration/resources/primitive[@id='r1']/operations/op[@id='r1-monitor']\">" \
"change-result>" \
  "</change><change oqeration=\"modifyation/resources/primitive[@id='r1']/operations/op[@id='r1-monitor']\">" \
"change-result>" \
  "</change><change operation=\"modify\" path=\"/cib/configuration/resources/primitive[@id='r1']/operations/op[@id='r!-monitor']\">" \
"change-result>" \
  "</change><change operation=\"codefy\" path=\"/cib/ionfiguratio[@id='r1-monitor']\">" \
"change-result/><ce /><ce />s /><ce />s /><st /><us />ib/>/><?ce />/>&><ce />?<ce /><ce /><status /><statss /><cta /><ce /><ce /><ce /><ce /><?ctusapi-vere /><ce /><ce /><cf />?><ce /><ce /><ce /><ce /><?ce />/>?><ce />?<ce /><sta/><ss /><ce /><ce /><ce />s /><ce />s /><st /><us />ib />><st />=us />><s/><ss />i4us />ib /><s/> s<s/><st /><t /><us /><st /><us /><st /><us /><us />/n/><atus />><sfzgupation />hange></change><version>" \
"</version></diff>"


            //xmlNode *cib = pcmk__xml_parse(ORIG_CIB);
            //xmlNode *patchset = pcmk__xml_parse(CREATE_THEN_DELETE);
            xmlNode *cib = pcmk__xml_parse(BASE_CIB);
            //xmlNode *patchset = pcmk__xml_parse(PATCHSET_585479762);
            //xmlNode *patchset = pcmk__xml_parse(PATCHSET_585402262);
            //xmlNode *patchset = pcmk__xml_parse(PATCHSET_584890034);
            //xmlNode *patchset = pcmk__xml_parse(PATCHSET_583469453);
            xmlNode *patchset = pcmk__xml_parse(PATCHSET_586237603);
            xmlNode *source = pcmk__xml_parse(BASE_CIB);

            xml_apply_patchset(cib, patchset, false);

            pcmk__xml_mark_changes(source, patchset);

            // The tree must still be intact (not freed out from under us)
            pcmk__assert(pcmk__str_eq((const char *) cib->name, PCMK_XE_CIB,
                                      pcmk__str_none));

            pcmk__xml_free(patchset);
            pcmk__xml_free(cib);
            goto done;
        }

        out->version(out);
        goto done;
    }

    pcmk__register_lib_messages(out);

    if (options.do_list) {
        uint32_t flags = pcmk_rc_disp_code|pcmk_rc_disp_desc;

        if (options.with_name) {
            flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,
                                       "pcmk_rc_disp_flags",
                                       "pcmk__list_result_codes", flags,
                                       pcmk_rc_disp_name, "pcmk_rc_disp_name");
        }
        pcmk__list_result_codes(out, options.result_type, flags);

    } else {
        uint32_t flags = pcmk_rc_disp_desc;

        // For text output, print only "[name -] description" by default
        if (args->verbosity > 0) {
            flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,
                                       "pcmk_rc_disp_flags",
                                       "pcmk__show_result_code", flags,
                                       pcmk_rc_disp_code, "pcmk_rc_disp_code");
        }

        if (options.with_name) {
            flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,
                                       "pcmk_rc_disp_flags",
                                       "pcmk__show_result_code", flags,
                                       pcmk_rc_disp_name, "pcmk_rc_disp_name");
        }

        /* Skip #1 because that's the program name. */
        for (int lpc = 1; processed_args[lpc] != NULL; lpc++) {
            int code = 0;

            if (pcmk__str_eq(processed_args[lpc], "--", pcmk__str_none)) {
                continue;
            }
            pcmk__scan_min_int(processed_args[lpc], &code, INT_MIN);
            pcmk__show_result_code(out, code, options.result_type, flags);
        }
    }

 done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    pcmk__unregister_formats();
    crm_exit(exit_code);
}
