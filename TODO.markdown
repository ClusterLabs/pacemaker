# Semi-random collection of tasks we'd like to get done

## Targeted for 1.2
- Need a way to indicate when unfencing operations need to be initiated from the host to be unfenced
- Remove all calls to uname() and replace with get_node_name() whcih redirects to ${stack}_node_name()
 
## Targeted for 1.2.x

- Support
  http://cgit.freedesktop.org/systemd/systemd/commit/?id=96342de68d0d6de71a062d984dafd2a0905ed9fe
- Allow stonith_admin to optionally route fencing requests via the CIB (terminate=true)
- Add corosync to ComponentFail cts test
- Support 'yesterday' and 'thursday' and '24-04' as dates in crm_report 
- Allow the N in 'give up after N failed fencing attempts' to be configurable 
- Check for uppercase letters in node names, warn if found
- Imply startup-failure-is-fatal from on-fail="restart" 
- Show an english version of the config with crm_resource --rules
- Convert cts/CIB.py into a supported Python API for the CIB
- Reduce the amount of stonith-ng logging
- Use dlopen for snmp in crm_mon
- Re-implement no-quorum filter for cib updates?

## Targeted for 1.4

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
- Document reload in Pacemaker Explained
- Document advanced fencing logic in Pacemaker Explained
- Use ann:defaultValue="..." instead of <optional> in the schema more often
- Document in CFS an Appendix detailing with re-enabling firewall
- Remove ocf:heartbeat part of resource create to demonstrate that the resource is automatically found.
- Document implicit operation creation in CFS once pcs supports it.
- Document use of pcs resource move command in CFS once pcs supports it.
- Make use of --clone option in pcs resource create dlm in CFS once pcs fully supports that option.
