# Semi-random collection of tasks we'd like to get done

## High priority

- Determine if we can support legacy Linux-HA fencing agents at runtime using dlopen() 
- Allow Clusters from Scratch to be built in two flavors - pcs and crm shell
- Convert cts/CIB.py into a supported Python API for the CIB
- Use crm_log_tag() in the PE to allow per-resource trace logging
- Write a regression test for Stonith-NG
- Listen and report on stonith events in crm_mon

## Medium priority

- Support heartbeat with the mcp
- Use the DBus API for controlling systemd services
- Reduce the amount of attrd logging
- Reduce the amount of stonith-ng logging
- Investigate the feasibility of using standard errno.h error codes for CIB, lrmd and Stonith-NG APIs
- Support A colocated with (B || C || D)

## Low priority

- Implement a truely atomic version of attrd
- Support rolling average values in attrd
- Remove instance numbers from anonymous clones
