.. index::
   pair: XML element; status

Status
------
Pacemaker automatically generates a ``status`` section in the CIB (inside the
``cib`` element, at the same level as ``configuration``). The status is
transient, and is not stored to disk with the rest of the CIB.

The section's structure and contents are internal to Pacemaker and subject to
change from release to release. Its often obscure element and attribute names
are kept for historical reasons, to maintain compatibility with older versions
during rolling upgrades.

Users should not modify the section directly, though various command-line tool
options affect it indirectly.


.. index::
   pair: XML element; node_state
   single: node; state
       
Node State
##########
   
The ``status`` element contains ``node_state`` elements for each node in the
cluster (and potentially nodes that have been removed from the configuration
since the cluster started). The ``node_state`` element has attributes that
allow the cluster to determine whether the node is healthy.

.. topic:: Example minimal node state entry

   .. code-block:: xml

      <node_state id="1" uname="cl-virt-1" in_ccm="1721760952" crmd="1721760952" crm-debug-origin="controld_update_resource_history" join="member" expected="member">
       <transient_attributes id="1"/>
       <lrm id="1"/>
      </node_state>
   
.. list-table:: **Attributes of a node_state Element**
   :class: longtable
   :widths: 1 1 3
   :header-rows: 1

   * - Name
     - Type
     - Description
   * - .. _node_state_id:

       .. index::
          pair: node_state; id

       id
     - :ref:`text <text>`
     - Node ID (identical to ``id`` of corresponding ``node`` element in the
       ``configuration`` section)
   * - .. node_state_uname:

       .. index::
          pair: node_state; uname

       uname
     - :ref:`text <text>`
     - Node name (identical to ``uname`` of corresponding ``node`` element in the
       ``configuration`` section)
   * - .. node_state_in_ccm:

       .. index::
          pair: node_state; in_ccm

       in_ccm
     - :ref:`epoch time <epoch_time>` *(since 2.1.7; previously boolean)*
     - If the node's controller is currently in the cluster layer's membership,
       this is the epoch time at which it joined (or 1 if the node is in the
       process of leaving the cluster), otherwise 0 *(since 2.1.7; previously,
       it was "true" or "false")*
   * - .. node_state_crmd:

       .. index::
          pair: node_state; crmd

       crmd
     - :ref:`epoch time <epoch_time>` *(since 2.1.7; previously an enumeration)*
     - If the node's controller is currently in the cluster layer's controller
       messaging group, this is the epoch time at which it joined, otherwise 0
       *(since 2.1.7; previously, the value was either "online" or "offline")*
   * - .. node_state_crm_debug_origin:

       .. index::
          pair: node_state; crm-debug-origin

       crm-debug-origin
     - :ref:`text <text>`
     - Name of the source code function that recorded this ``node_state``
       element (for debugging)
   * - .. node_state_join:

       .. index::
          pair: node_state; join

       join
     - :ref:`enumeration <enumeration>`
     - Current status of node's controller join sequence (and thus whether it
       is eligible to run resources). Allowed values:

       * ``down``: Not yet joined
       * ``pending``: In the process of joining or leaving
       * ``member``: Fully joined
       * ``banned``: Rejected by DC
   * - .. node_state_expected:

       .. index::
          pair: node_state; expected

       expected
     - :ref:`enumeration <enumeration>`
     - What cluster expects ``join`` to be in the immediate future. Allowed
       values are same as for ``join``.


.. _transient_attributes:

.. index::
   pair: XML element; transient_attributes
   single: node; transient attribute
   single: node attribute; transient

Transient Node Attributes
#########################
   
The ``transient_attributes`` section specifies transient
:ref:`node_attributes`. In addition to any values set by the administrator or
resource agents using the ``attrd_updater`` or ``crm_attribute`` tools, the
cluster stores various state information here.
         
.. topic:: Example transient node attributes for a node

   .. code-block:: xml
   
      <transient_attributes id="cl-virt-1">
        <instance_attributes id="status-cl-virt-1">
           <nvpair id="status-cl-virt-1-pingd" name="pingd" value="3"/>
           <nvpair id="status-cl-virt-1-fail-count-pingd:0.monitor_30000" name="fail-count-pingd:0#monitor_30000" value="1"/>
           <nvpair id="status-cl-virt-1-last-failure-pingd:0" name="last-failure-pingd:0" value="1239009742"/>
        </instance_attributes>
      </transient_attributes>
   

.. index::
   pair: XML element; lrm
   pair: XML element; lrm_resources
   pair: node; history

Node History
############

Each ``node_state`` element contains an ``lrm`` element with a history of
certain resource actions performed on the node. The ``lrm`` element contains an
``lrm_resources`` element.

.. index::
   pair: XML element; lrm_resource
   pair: resource; history

Resource History
________________

The ``lrm_resources`` element contains an ``lrm_resource`` element for each
resource that has had an action performed on the node.

An ``lrm_resource`` entry has attributes allowing the cluster to stop the
resource safely even if it is removed from the configuration. Specifically, the
resource's ``id``, ``class``, ``type`` and ``provider`` are recorded.

.. index::
   pair: XML element; lrm_rsc_op
   pair: action; history

Action History
______________

Each ``lrm_resource`` element contains an ``lrm_rsc_op`` element for each
recorded action performed for that resource on that node. (Not all actions are
recorded, just enough to determine the resource's state.)

.. list-table:: **Attributes of an lrm_rsc_op element**
   :class: longtable
   :widths: 1 1 3
   :header-rows: 1

   * - Name
     - Type
     - Description
   * - .. _lrm_rsc_op_id:

       .. index::
          pair: lrm_rsc_op; id

       id
     - :ref:`text <text>`
     - Identifier for the history entry constructed from the resource ID,
       action name or history entry type, and action interval.
   * - .. _lrm_rsc_op_operation_key:

       .. index::
          pair: lrm_rsc_op; operation_key

       operation_key
     - :ref:`text <text>`
     - Identifier for the action that was executed, constructed from the
       resource ID, action name, and action interval.
   * - .. _lrm_rsc_op_operation:

       .. index::
          pair: lrm_rsc_op; operation

       operation
     - :ref:`text <text>`
     - The name of the action the history entry is for
   * - .. _lrm_rsc_op_crm_debug_origin:

       .. index::
          pair: lrm_rsc_op; crm-debug-origin

       crm-debug-origin
     - :ref:`text <text>`
     - Name of the source code function that recorded this entry (for
       debugging)
   * - .. _lrm_rsc_op_crm_feature_set:

       .. index::
          pair: lrm_rsc_op; crm_feature_set

       crm_feature_set
     - :ref:`version <version>`
     - The Pacemaker feature set used to record this entry.
   * - .. _lrm_rsc_op_transition_key:

       .. index::
          pair: lrm_rsc_op; transition-key

       transition-key
     - :ref:`text <text>`
     - A concatenation of the action's transition graph action number, the
       transition graph number, the action's expected result, and the UUID of
       the controller instance that scheduled it.
   * - .. _lrm_rsc_op_transition_magic:

       .. index::
          pair: lrm_rsc_op; transition-magic

       transition-magic
     - :ref:`text <text>`
     - A concatenation of ``op-status``, ``rc-code``, and ``transition-key``.
   * - .. _lrm_rsc_op_exit_reason:

       .. index::
          pair: lrm_rsc_op; exit-reason

       exit-reason
     - :ref:`text <text>`
     - An error message (if available) from the resource agent or Pacemaker if
       the action did not return success.
   * - .. _lrm_rsc_op_on_node:

       .. index::
          pair: lrm_rsc_op; on_node

       on_node
     - :ref:`text <text>`
     - The name of the node that executed the action (identical to the
       ``uname`` of the enclosing ``node_state`` element)
   * - .. _lrm_rsc_op_call_id:

       .. index::
          pair: lrm_rsc_op; call-id

       call-id
     - :ref:`integer <integer>`
     - A node-specific counter used to determine the order in which actions
       were executed.
   * - .. _lrm_rsc_op_rc_code:

       .. index::
          pair: lrm_rsc_op; rc-code

       rc-code
     - :ref:`integer <integer>`
     - The resource agent's exit status for this action. Refer to the *Resource
       Agents* chapter of *Pacemaker Administration* for how these values are
       interpreted.
   * - .. _lrm_rsc_op_op_status:

       .. index::
          pair: lrm_rsc_op; op-status

       op-status
     - :ref:`integer <integer>`
     - The execution status of this action. The meanings of these codes are
       internal to Pacemaker.
   * - .. _lrm_rsc_op_interval:

       .. index::
          pair: lrm_rsc_op; interval

       interval
     - :ref:`nonnegative integer <nonnegative_integer>`
     - If the action is recurring, its frequency (in milliseconds), otherwise
       0.
   * - .. _lrm_rsc_op_last_rc_change:

       .. index::
          pair: lrm_rsc_op; last-rc-change

       last-rc-change
     - :ref:`epoch time <epoch_time>`
     - Node-local time at which the action first returned the current value of
       ``rc-code``.
   * - .. _lrm_rsc_op_exec_time:

       .. index::
          pair: lrm_rsc_op; exec-time

       exec-time
     - :ref:`integer <integer>`
     - Time (in seconds) that action execution took (if known)
   * - .. _lrm_rsc_op_queue_time:

       .. index::
          pair: lrm_rsc_op; queue-time

       queue-time
     - :ref:`integer <integer>`
     - Time (in seconds) that action was queued in the local executor (if known)
   * - .. _lrm_rsc_op_op_digest:

       .. index::
          pair: lrm_rsc_op; op-digest

       op-digest
     - :ref:`text <text>`
     - If present, this is a hash of the parameters passed to the action. If a
       hash of the currently configured parameters does not match this, that
       means the resource configuration changed since the action was performed,
       and the resource must be reloaded or restarted.
   * - .. _lrm_rsc_op_op_restart_digest:

       .. index::
          pair: lrm_rsc_op; op-restart-digest

       op-restart-digest
     - :ref:`text <text>`
     - If present, the resource agent supports reloadable parameters, and this
       is a hash of the non-reloadable parameters passed to the action. This
       allows the cluster to choose between reload and restart when one is
       needed.
   * - .. _lrm_rsc_op_op_secure_digest:

       .. index::
          pair: lrm_rsc_op; op-secure-digest

       op-secure-digest
     - :ref:`text <text>`
     - If present, the resource agent marks some parameters as sensitive, and
       this is a hash of the non-sensitive parameters passed to the action.
       This allows the value of sensitive parameters to be removed from a saved
       copy of the CIB while still allowing scheduler simulations to be
       performed on that copy.


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

The above example shows the history entry for a probe (non-recurring monitor
operation) for the ``apcstonith`` resource.

The cluster schedules probes for every configured resource on a node when
the node first starts, in order to determine the resource's current state
before it takes any further action.
       
From the ``transition-key``, we can see that this was the 22nd action of
the 2nd graph produced by this instance of the controller
(2668bbeb-06d5-40f9-936d-24cb7f87006a).

The third field of the ``transition-key`` contains a 7, which indicates
that the cluster expects to find the resource inactive. By looking at the
``rc-code`` property, we see that this was the case.

As that is the only action recorded for this node, we can conclude that
the cluster started the resource elsewhere.
   
Complex Operation History Example
_________________________________
           
.. topic:: Resource history of a ``pingd`` clone with multiple entries

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
   
When more than one history entry exists, it is important to first sort
them by ``call-id`` before interpreting them.

Once sorted, the above example can be summarized as:

#. A non-recurring monitor operation returning 7 (not running), with a
   ``call-id`` of 3
#. A stop operation returning 0 (success), with a ``call-id`` of 32
#. A start operation returning 0 (success), with a ``call-id`` of 33
#. A recurring monitor returning 0 (success), with a ``call-id`` of 34

The cluster processes each history entry to build up a picture of the
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
