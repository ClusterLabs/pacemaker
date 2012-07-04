# Semi-random collection of tasks we'd like to get done

## Targeted for 1.2
- Have crm_mon listen for stonith events (and send email/snmp traps)
- Block after N stonith failures (per node)

- Need a way to indicate when unfencing operations need to be initiated from the host to be unfenced

- Figure out how to sanely allow nodes with corosync but no pacemaker
  - sysconfig variable that tells pacemaker whether to fence members without pacemaker?
- Arrange for nodes that didnt complete the join to be fenced

- Remove instance numbers from anonymous clones
- Create a proper struct for stonith notify events

## Targeted for 1.2.x

- Check for uppercase letters in node names, warn if found
- Imply startup-failure-is-fatal from on-fail="restart" 
- Show an english version of the config with crm_resource --rules
- Convert cts/CIB.py into a supported Python API for the CIB
- Use crm_log_tag() in the PE to allow per-resource trace logging
- Reduce the amount of stonith-ng logging
- Reduce the amount of attrd logging
- Use dlopen for snmp


## Targeted for 1.4

- Support A colocated with (B || C || D)
- Implement a truely atomic version of attrd
- Support rolling average values in attrd
- Support heartbeat with the mcp
- Freeze/Thaw
- Create Pacemaker plugin for snmpd - http://www.net-snmp.org/
- Investigate using a DB as the back-end for the CIB

# Testing
- Write a regression test for Stonith-NG
- Convert BandwidthTest CTS test into a Scenario wrapper
- find_operations() is not covered by PE regression tests
- Some node states in determine_online_status_fencing() are untested by PE regression tests
- no_quorum_policy==suicide is not covered by PE regression tests
- parse_xml_duration() is not covered by PE regression tests
- phase_of_the_moon() is not covered by PE regression tests
- test_role_expression() is not covered by PE regression tests
- native_parameter() is not covered by PE regression tests
- clone_resource_state() is not covered by PE regression tests
- clone_active() is not covered by PE regression tests
- convert_non_atomic_task() in native.c is not covered by PE regression tests
- clone_rsc_colocation_lh() is not covered by PE regression tests
- group_rsc_colocation_lh() is not covered by PE regression tests
- Test on-fail=standby

# Documentation
- Clusters from Scratch: Mail
- Clusters from Scratch: MySQL
- Document reload in Pacemaker Explained
- Use ann:defaultValue="..." instead of <optional> in the schema more often
- Allow Clusters from Scratch to be built in two flavors - pcs and crm shell
