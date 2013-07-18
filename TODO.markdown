# Semi-random collection of tasks we'd like to get done

## Targeted for this year

- Implement:
 - crm_node --standby
 - crm_resource --enable --recursive :  set target role for anything we depend on
 - crm_resource --force-start <-- check resource is stopped

- Only bump epoch if we have quorum when we are elected the DC 
- Bump epoch if we gain quorum and are the DC

- Make sure crm_attribute/crmd writes direct to cib if attrd is not around
- See if anywhere should be using clock_gettime() instead of time(NULL)
- Make sure fail counts etc are removed on resource deletion

- Test and merge ipc-dispatch.patch
- Process election votes as soon as they happen
  notice: do_election_count_vote: Election 6 (current: 6, owner: 101): Processed no-vote from east-04 (Peer is not part of our cluster)

- Support
  http://cgit.freedesktop.org/systemd/systemd/commit/?id=96342de68d0d6de71a062d984dafd2a0905ed9fe
- Support 'yesterday' and 'thursday' and '24-04' as dates in crm_report 
- Allow the N in 'give up after N failed fencing attempts' to be configurable 
- Show an english version of the config with crm_resource --rules
- Convert cts/CIB.py into a supported Python API for the CIB
- Re-implement no-quorum filter for cib updates?

## Targeted for next year and beyond

- Support A colocated with (B || C || D)
- Implement a truely atomic version of attrd
- Support rolling average values in attrd
- Support heartbeat with the mcp
- Freeze/Thaw
- Create Pacemaker plugin for snmpd - http://www.net-snmp.org/
- Investigate using a DB as the back-end for the CIB
- Decide whether to fully support or drop failover domains

# Testing
- Convert BandwidthTest CTS test into a Scenario wrapper
- find_operations() is not covered by PE regression tests
- no_quorum_policy==suicide is not covered by PE regression tests
- parse_xml_duration() is not covered by PE regression tests
- phase_of_the_moon() is not covered by PE regression tests
- test_role_expression() is not covered by PE regression tests
- native_parameter() is not covered by PE regression tests
- clone_active() is not covered by PE regression tests
- convert_non_atomic_task() in native.c is not covered by PE regression tests
- group_rsc_colocation_lh() is not covered by PE regression tests
- Test on-fail=standby

# Documentation
- Clusters from Scratch: Mail
- Clusters from Scratch: MySQL
- Document advanced fencing logic in Pacemaker Explained
- Use ann:defaultValue="..." instead of <optional> in the schema more often
- Document in CFS an Appendix detailing with re-enabling firewall
- Document implicit operation creation in CFS once pcs supports it.
- Document use of pcs resource move command in CFS once pcs supports it.
- Make use of --clone option in pcs resource create dlm in CFS once pcs fully supports that option.
