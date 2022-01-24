#ifndef PCMK__PCMKI_PCMKI_CLUSTER_QUERIES__H
#  define PCMK__PCMKI_PCMKI_CLUSTER_QUERIES__H

#include <glib.h>               // gboolean, GMainLoop, etc.

#include <crm/crm.h>
#include <crm/common/output_internal.h>
#include <crm/common/ipc_controld.h>
#include <crm/common/ipc_pacemakerd.h>

int pcmk__controller_status(pcmk__output_t *out, char *dest_node, guint message_timeout_ms);
int pcmk__designated_controller(pcmk__output_t *out, guint message_timeout_ms);
int pcmk__pacemakerd_status(pcmk__output_t *out, char *ipc_name, guint message_timeout_ms);
int pcmk__list_nodes(pcmk__output_t *out, char *node_types, gboolean BASH_EXPORT);

#endif
