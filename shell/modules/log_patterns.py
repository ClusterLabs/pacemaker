# Copyright (C) 2011 Dejan Muhamedagic <dmuhamedagic@suse.de>
#
# log pattern specification
#
# patterns are grouped one of several classes:
#  - resources: pertaining to a resource
#  - node: pertaining to a node
#  - quorum: quorum changes
#  - events: other interesting events (core dumps, etc)
# 
# paterns are grouped based on a detail level
# detail level 0 is the lowest, i.e. should match the least
# number of relevant messages

# NB: If you modify this file, you must follow python syntax!

log_patterns = {
	"resource": (
		( # detail 0
			"lrmd:.*rsc:%%.*(start|stop)",
			"lrmd:.*RA output:.*%%.*stderr",
			"lrmd:.*WARN:.*Managed.*%%.*exited",
		),
		( # detail 1
			"lrmd:.*rsc:%%.*probe",
			"lrmd:.*info:.*Managed.*%%.*exited",
		),
	),
	"node": (
		( # detail 0
			"%%.*Corosync.Cluster.Engine",
			"%%.*Executive.Service.RELEASE",
			"%%.*crm_shutdown:.Requesting.shutdown",
			"%%.*pcmk_shutdown:.Shutdown.complete",
			"%%.*Configuration.validated..Starting.heartbeat",
			"pengine.*Scheduling Node %%",
			"te_fence_node.*Exec.*%%",
			"stonith-ng.*log_oper.*reboot.*%%",
			"stonithd.*to STONITH.*%%",
			"stonithd.*fenced node %%",
			"pcmk_peer_update.*(lost|memb): %%",
			"crmd.*ccm_event.*(NEW|LOST) %%",
		),
		( # detail 1
		),
	),
	"quorum": (
		( # detail 0
			"crmd.*crm_update_quorum:.Updating.quorum.status",
			"crmd.*ais.disp.*quorum.(lost|ac?quir)",
		),
		( # detail 1
		),
	),
	"events": (
		( # detail 0
			"CRIT:",
			"ERROR:",
		),
		( # detail 1
			"WARN:",
		),
	),
}

transition_patt = (
	"crmd: .* Processing graph.*derived from .*/pe-[^-]+-(%%)[.]bz2", # transition start
	"crmd: .* Transition.*Source=.*/pe-[^-]+-(%%)[.]bz2.: (Stopped|Complete|Terminated)", # and stop
)
