#ifndef TENGINE__H
#define TENGINE__H

extern gboolean initialize_graph(void);
extern gboolean unpack_graph(xmlNodePtr xml_graph);
extern gboolean process_event(xmlNodePtr msg);
extern gboolean initiate_transition(void);
extern gboolean te_input_dispatch(IPC_Channel *sender, void *user_data);
extern void process_te_message(xmlNodePtr msg);

extern IPC_Channel *crm_ch;

#endif


