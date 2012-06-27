# Semi-random collection of tasks we'd like to get done

## Targeted for 1.2
- Investigate the feasibility of using standard errno.h error codes for CIB, lrmd and Stonith-NG APIs
- Determine if we can support legacy Linux-HA fencing agents at runtime using dlopen() 
- Listen and report on stonith events in crm_mon
- Have lrmd/regression.py produce and keep debug logs from the lrmd
- Add upstart tests to lrmd/regression.py

## Targeted for 1.2.x

- Convert cts/CIB.py into a supported Python API for the CIB
- Use crm_log_tag() in the PE to allow per-resource trace logging
- Write a regression test for Stonith-NG
- Allow Clusters from Scratch to be built in two flavors - pcs and crm shell
- Make lrmd/regression.py smart enough to only run upstart/systemd tests if the host supports it
- Reduce the amount of attrd logging
- Reduce the amount of stonith-ng logging

## Targeted for 1.4

- Support A colocated with (B || C || D)
- Implement a truely atomic version of attrd
- Support rolling average values in attrd
- Remove instance numbers from anonymous clones
- Support heartbeat with the mcp


