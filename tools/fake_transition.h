void modify_configuration(
    pe_working_set_t * data_set, cib_t *cib,
    const char *quorum, const char *watchdog, GListPtr node_up, GListPtr node_down, GListPtr node_fail,
    GListPtr op_inject, GListPtr ticket_grant, GListPtr ticket_revoke,
    GListPtr ticket_standby, GListPtr ticket_activate);

int run_simulation(pe_working_set_t * data_set, cib_t *cib, GListPtr op_fail_list, bool quiet);

