.. index::
   single: status
   single: XML element, status

Status -- Here be dragons
-------------------------

Most users never need to understand the contents of the status section
and can be happy with the output from ``crm_mon``.

However for those with a curious inclination, this section attempts to
provide an overview of its contents.

.. index::
   single: node; status
       
Node Status
###########
   
In addition to the cluster's configuration, the CIB holds an
up-to-date representation of each cluster node in the ``status`` section.

.. topic:: A bare-bones status entry for a healthy node **cl-virt-1**

   .. code-block:: xml

      <node_state id="1" uname="cl-virt-1" in_ccm="true" crmd="online" crm-debug-origin="do_update_resource" join="member" expected="member">
       <transient_attributes id="1"/>
       <lrm id="1"/>
      </node_state>
   
Users are highly recommended *not* to modify any part of a node's
state *directly*.  The cluster will periodically regenerate the entire
section from authoritative sources, so any changes should be done
with the tools appropriate to those sources.
         
.. table:: **Authoritative Sources for State Information**
   :widths: 1 1

   +----------------------+----------------------+
   | CIB Object           | Authoritative Source |
   +======================+======================+
   | node_state           | pacemaker-controld   |
   +----------------------+----------------------+
   | transient_attributes | pacemaker-attrd      |
   +----------------------+----------------------+
   | lrm                  | pacemaker-execd      |
   +----------------------+----------------------+

The fields used in the ``node_state`` objects are named as they are
largely for historical reasons and are rooted in Pacemaker's origins
as the resource manager for the older Heartbeat project. They have remained
unchanged to preserve compatibility with older versions.
         
.. table:: **Node Status Fields**
   :widths: 1 3

   +------------------+----------------------------------------------------------+
   | Field            | Description                                              |
   +==================+==========================================================+
   | id               | .. index:                                                |
   |                  |    single: id; node status                               |
   |                  |    single: node; status, id                              |
   |                  |                                                          |
   |                  | Unique identifier for the node.  Corosync-based clusters |
   |                  | use a numeric counter.                                   |
   +------------------+----------------------------------------------------------+
   | uname            | .. index::                                               |
   |                  |    single: uname; node status                            |
   |                  |    single: node; status, uname                           |
   |                  |                                                          |
   |                  | The node's name as known by the cluster                  |
   +------------------+----------------------------------------------------------+
   | in_ccm           | .. index::                                               |
   |                  |    single: in_ccm; node status                           |
   |                  |    single: node; status, in_ccm                          |
   |                  |                                                          |
   |                  | Is the node a member at the cluster communication later? |
   |                  | Allowed values: ``true``, ``false``.                     |
   +------------------+----------------------------------------------------------+
   | crmd             | .. index::                                               |
   |                  |    single: crmd; node status                             |
   |                  |    single: node; status, crmd                            |
   |                  |                                                          |
   |                  | Is the node a member at the pacemaker layer?  Allowed    |
   |                  | values: ``online``, ``offline``.                         |
   +------------------+----------------------------------------------------------+
   | crm-debug-origin | .. index::                                               |
   |                  |    single: crm-debug-origin; node status                 |
   |                  |    single: node; status, crm-debug-origin                |
   |                  |                                                          |
   |                  | The name of the source function that made the most       |
   |                  | recent change (for debugging purposes).                  |
   +------------------+----------------------------------------------------------+
   | join             | .. index::                                               |
   |                  |    single: join; node status                             |
   |                  |    single: node; status, join                            |
   |                  |                                                          |
   |                  | Does the node participate in hosting resources?          |
   |                  | Allowed values: ``down``, ``pending``, ``member``.       |
   |                  | ``banned``.                                              |
   +------------------+----------------------------------------------------------+
   | expected         | .. index::                                               |
   |                  |   single: expected; node status                          |
   |                  |   single: node; status, expected                         |
   |                  |                                                          |
   |                  | Expected value for ``join``.                             |
   +------------------+----------------------------------------------------------+
   
The cluster uses these fields to determine whether, at the node level, the
node is healthy or is in a failed state and needs to be fenced.
   
Transient Node Attributes
#########################
   
Like regular :ref:`node_attributes`, the name/value
pairs listed in the ``transient_attributes`` section help to describe the
node.  However they are forgotten by the cluster when the node goes offline.
This can be useful, for instance, when you want a node to be in standby mode
(not able to run resources) just until the next reboot.
     
In addition to any values the administrator sets, the cluster will
also store information about failed resources here.
         
.. topic:: A set of transient node attributes for node **cl-virt-1**

   .. code-block:: xml
   
      <transient_attributes id="cl-virt-1">
        <instance_attributes id="status-cl-virt-1">
           <nvpair id="status-cl-virt-1-pingd" name="pingd" value="3"/>
           <nvpair id="status-cl-virt-1-probe_complete" name="probe_complete" value="true"/>
           <nvpair id="status-cl-virt-1-fail-count-pingd:0.monitor_30000" name="fail-count-pingd:0#monitor_30000" value="1"/>
           <nvpair id="status-cl-virt-1-last-failure-pingd:0" name="last-failure-pingd:0" value="1239009742"/>
        </instance_attributes>
      </transient_attributes>
   
In the above example, we can see that a monitor on the ``pingd:0`` resource has
failed once, at 09:22:22 UTC 6 April 2009. [#]_.

We also see that the node is connected to three **pingd** peers and that
all known resources have been checked for on this machine (``probe_complete``).
         
.. index::
   single: Operation History

Operation History
#################
   
A node's resource history is held in the ``lrm_resources`` tag (a child
of the ``lrm`` tag). The information stored here includes enough
information for the cluster to stop the resource safely if it is
removed from the ``configuration`` section. Specifically, the resource's
``id``, ``class``, ``type`` and ``provider`` are stored.

.. topic:: A record of the ``apcstonith`` resource

   .. code-block:: xml

      <lrm_resource id="apcstonith" type="fence_apc_snmp" class="stonith"/>
   
Additionally, we store the last job for every combination of
``resource``, ``action`` and ``interval``.  The concatenation of the values in
this tuple are used to create the id of the ``lrm_rsc_op`` object.

.. table:: **Contents of an lrm_rsc_op job**
   :class: longtable
   :widths: 1 3

   +------------------+----------------------------------------------------------+
   | Field            | Description                                              |
   +==================+==========================================================+
   | id               | .. index::                                               |
   |                  |    single: id; action status                             |
   |                  |    single: action; status, id                            |
   |                  |                                                          |
   |                  | Identifier for the job constructed from the resource's   |
   |                  | ``operation`` and ``interval``.                          |
   +------------------+----------------------------------------------------------+
   | call-id          | .. index::                                               |
   |                  |    single: call-id; action status                        |
   |                  |    single: action; status, call-id                       |
   |                  |                                                          |
   |                  | The job's ticket number. Used as a sort key to determine |
   |                  | the order in which the jobs were executed.               |
   +------------------+----------------------------------------------------------+
   | operation        | .. index::                                               |
   |                  |    single: operation; action status                      |
   |                  |    single: action; status, operation                     |
   |                  |                                                          |
   |                  | The action the resource agent was invoked with.          |
   +------------------+----------------------------------------------------------+
   | interval         | .. index::                                               |
   |                  |    single: interval; action status                       |
   |                  |    single: action; status, interval                      |
   |                  |                                                          |
   |                  | The frequency, in milliseconds, at which the operation   |
   |                  | will be repeated. A one-off job is indicated by 0.       |
   +------------------+----------------------------------------------------------+
   | op-status        | .. index::                                               |
   |                  |    single: op-status; action status                      |
   |                  |    single: action; status, op-status                     |
   |                  |                                                          |
   |                  | The job's status. Generally this will be either 0 (done) |
   |                  | or -1 (pending). Rarely used in favor of ``rc-code``.    |
   +------------------+----------------------------------------------------------+
   | rc-code          | .. index::                                               |
   |                  |    single: rc-code; action status                        |
   |                  |    single: action; status, rc-code                       |
   |                  |                                                          |
   |                  | The job's result. Refer to the *Resource Agents* chapter |
   |                  | of *Pacemaker Administration* for details on what the    |
   |                  | values here mean and how they are interpreted.           |
   +------------------+----------------------------------------------------------+
   | last-rc-change   | .. index::                                               |
   |                  |    single: last-rc-change; action status                 |
   |                  |    single: action; status, last-rc-change                |
   |                  |                                                          |
   |                  | Machine-local date/time, in seconds since epoch, at      |
   |                  | which the job first returned the current value of        |
   |                  | ``rc-code``.  For diagnostic purposes.                   |
   +------------------+----------------------------------------------------------+
   | exec-time        | .. index::                                               |
   |                  |    single: exec-time; action status                      |
   |                  |    single: action; status, exec-time                     |
   |                  |                                                          |
   |                  | Time, in milliseconds, that the job was running for.     |
   |                  | For diagnostic purposes.                                 |
   +------------------+----------------------------------------------------------+
   | queue-time       | .. index::                                               |
   |                  |    single: queue-time; action status                     |
   |                  |    single: action; status, queue-time                    |
   |                  |                                                          |
   |                  | Time, in seconds, that the job was queued for in the     |
   |                  | local executor. For diagnostic purposes.                 |
   +------------------+----------------------------------------------------------+
   | crm_feature_set  | .. index::                                               |
   |                  |    single: crm_feature_set; action status                |
   |                  |    single: action; status, crm_feature_set               |
   |                  |                                                          |
   |                  | The version which this job description conforms to. Used |
   |                  | when processing ``op-digest``.                           |
   +------------------+----------------------------------------------------------+
   | transition-key   | .. index::                                               |
   |                  |    single: transition-key; action status                 |
   |                  |    single: action; status, transition-key                |
   |                  |                                                          |
   |                  | A concatenation of the job's graph action number, the    |
   |                  | graph number, the expected result and the UUID of the    |
   |                  | controller instance that scheduled it. This is used to   |
   |                  | construct ``transition-magic`` (below).                  |
   +------------------+----------------------------------------------------------+
   | transition-magic | .. index::                                               |
   |                  |    single: transition-magic; action status               |
   |                  |    single: action; status, transition-magic              |
   |                  |                                                          |
   |                  | A concatenation of the job's ``op-status``, ``rc-code``  |
   |                  | and ``transition-key``. Guaranteed to be unique for the  |
   |                  | life of the cluster (which ensures it is part of CIB     |
   |                  | update notifications) and contains all the information   |
   |                  | needed for the controller to correctly analyze and       |
   |                  | process the completed job. Most importantly, the         |
   |                  | decomposed elements tell the controller if the job       |
   |                  | entry was expected and whether it failed.                |
   +------------------+----------------------------------------------------------+
   | op-digest        | .. index::                                               |
   |                  |    single: op-digest; action status                      |
   |                  |    single: action; status, op-digest                     |
   |                  |                                                          |
   |                  | An MD5 sum representing the parameters passed to the     |
   |                  | job. Used to detect changes to the configuration, to     |
   |                  | restart resources if necessary.                          |
   +------------------+----------------------------------------------------------+
   | crm-debug-origin | .. index::                                               |
   |                  |    single: crm-debug-origin; action status               |
   |                  |    single: action; status, crm-debug-origin              |
   |                  |                                                          |
   |                  | The origin of the current values.  For diagnostic        |
   |                  | purposes.                                                |
   +------------------+----------------------------------------------------------+
   
Simple Operation History Example
________________________________
           
.. topic:: A monitor operation (determines current state of the ``apcstonith`` resource)

   .. code-block:: xml

      <lrm_resource id="apcstonith" type="fence_apc_snmp" class="stonith">
        <lrm_rsc_op id="apcstonith_monitor_0" operation="monitor" call-id="2"
          rc-code="7" op-status="0" interval="0"
          crm-debug-origin="do_update_resource" crm_feature_set="3.0.1"
          op-digest="2e3da9274d3550dc6526fb24bfcbcba0"
          transition-key="22:2:7:2668bbeb-06d5-40f9-936d-24cb7f87006a"
          transition-magic="0:7;22:2:7:2668bbeb-06d5-40f9-936d-24cb7f87006a"
          last-rc-change="1239008085" exec-time="10" queue-time="0"/>
      </lrm_resource>

In the above example, the job is a non-recurring monitor operation
often referred to as a "probe" for the ``apcstonith`` resource.

The cluster schedules probes for every configured resource on a node when
the node first starts, in order to determine the resource's current state
before it takes any further action.
       
From the ``transition-key``, we can see that this was the 22nd action of
the 2nd graph produced by this instance of the controller
(2668bbeb-06d5-40f9-936d-24cb7f87006a).

The third field of the ``transition-key`` contains a 7, which indicates
that the job expects to find the resource inactive. By looking at the ``rc-code``
property, we see that this was the case.

As that is the only job recorded for this node, we can conclude that
the cluster started the resource elsewhere.
   
Complex Operation History Example
_________________________________
           
.. topic:: Resource history of a ``pingd`` clone with multiple jobs

   .. code-block:: xml

      <lrm_resource id="pingd:0" type="pingd" class="ocf" provider="pacemaker">
        <lrm_rsc_op id="pingd:0_monitor_30000" operation="monitor" call-id="34"
          rc-code="0" op-status="0" interval="30000"
          crm-debug-origin="do_update_resource" crm_feature_set="3.0.1"
          transition-key="10:11:0:2668bbeb-06d5-40f9-936d-24cb7f87006a"
          last-rc-change="1239009741" exec-time="10" queue-time="0"/>
        <lrm_rsc_op id="pingd:0_stop_0" operation="stop"
          crm-debug-origin="do_update_resource" crm_feature_set="3.0.1" call-id="32"
          rc-code="0" op-status="0" interval="0"
          transition-key="11:11:0:2668bbeb-06d5-40f9-936d-24cb7f87006a"
          last-rc-change="1239009741" exec-time="10" queue-time="0"/>
        <lrm_rsc_op id="pingd:0_start_0" operation="start" call-id="33"
          rc-code="0" op-status="0" interval="0"
          crm-debug-origin="do_update_resource" crm_feature_set="3.0.1"
          transition-key="31:11:0:2668bbeb-06d5-40f9-936d-24cb7f87006a"
          last-rc-change="1239009741" exec-time="10" queue-time="0" />
        <lrm_rsc_op id="pingd:0_monitor_0" operation="monitor" call-id="3"
          rc-code="0" op-status="0" interval="0"
          crm-debug-origin="do_update_resource" crm_feature_set="3.0.1"
          transition-key="23:2:7:2668bbeb-06d5-40f9-936d-24cb7f87006a"
          last-rc-change="1239008085" exec-time="20" queue-time="0"/>
        </lrm_resource>
   
When more than one job record exists, it is important to first sort
them by ``call-id`` before interpreting them.

Once sorted, the above example can be summarized as:

#. A non-recurring monitor operation returning 7 (not running), with a ``call-id`` of 3
#. A stop operation returning 0 (success), with a ``call-id`` of 32
#. A start operation returning 0 (success), with a ``call-id`` of 33
#. A recurring monitor returning 0 (success), with a ``call-id`` of 34

The cluster processes each job record to build up a picture of the
resource's state.  After the first and second entries, it is
considered stopped, and after the third it considered active.

Based on the last operation, we can tell that the resource is
currently active.

Additionally, from the presence of a ``stop`` operation with a lower
``call-id`` than that of the ``start`` operation, we can conclude that the
resource has been restarted.  Specifically this occurred as part of
actions 11 and 31 of transition 11 from the controller instance with the key
``2668bbeb...``.  This information can be helpful for locating the
relevant section of the logs when looking for the source of a failure.

.. [#] You can use the standard ``date`` command to print a human-readable version
       of any seconds-since-epoch value, for example ``date -d @1239009742``.
