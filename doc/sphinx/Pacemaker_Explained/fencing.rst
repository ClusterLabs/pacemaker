.. index::
   single: fencing
   single: STONITH

.. _fencing:

Fencing
-------

What Is Fencing?
################

*Fencing* is the ability to make a node unable to run resources, even when that
node is unresponsive to cluster commands.

Fencing is also known as *STONITH*, an acronym for "Shoot The Other Node In The
Head", since the most common fencing method is cutting power to the node.
Another method is "fabric fencing", cutting the node's access to some
capability required to run resources (such as network access or a shared disk).

.. index::
   single: fencing; why necessary

Why Is Fencing Necessary?
#########################

Fencing protects your data from being corrupted by malfunctioning nodes or
unintentional concurrent access to shared resources.

Fencing protects against the "split brain" failure scenario, where cluster
nodes have lost the ability to reliably communicate with each other but are
still able to run resources. If the cluster just assumed that uncommunicative
nodes were down, then multiple instances of a resource could be started on
different nodes.

The effect of split brain depends on the resource type. For example, an IP
address brought up on two hosts on a network will cause packets to randomly be
sent to one or the other host, rendering the IP useless. For a database or
clustered file system, the effect could be much more severe, causing data
corruption or divergence.

Fencing is also used when a resource cannot otherwise be stopped. If a
resource fails to stop on a node, it cannot be started on a different node
without risking the same type of conflict as split-brain. Fencing the
original node ensures the resource can be safely started elsewhere.

Users may also configure the ``on-fail`` property of :ref:`operation` or the
``loss-policy`` property of
:ref:`ticket constraints <ticket-constraints>` to ``fence``, in which
case the cluster will fence the resource's node if the operation fails or the
ticket is lost.

.. index::
   single: fencing; device

Fence Devices
#############

A *fence device* or *fencing device* is a special type of resource that
provides the means to fence a node.

Examples of fencing devices include intelligent power switches and IPMI devices
that accept SNMP commands to cut power to a node, and iSCSI controllers that
allow SCSI reservations to be used to cut a node's access to a shared disk.

Since fencing devices will be used to recover from loss of networking
connectivity to other nodes, it is essential that they do not rely on the same
network as the cluster itself, otherwise that network becomes a single point of
failure.

Since loss of a node due to power outage is indistinguishable from loss of
network connectivity to that node, it is also essential that at least one fence
device for a node does not share power with that node. For example, an on-board
IPMI controller that shares power with its host should not be used as the sole
fencing device for that host.

Since fencing is used to isolate malfunctioning nodes, no fence device should
rely on its target functioning properly. This includes, for example, devices
that ssh into a node and issue a shutdown command (such devices might be
suitable for testing, but never for production).

.. index::
   single: fencing; agent

Fence Agents
############

A *fence agent* or *fencing agent* is a ``stonith``-class resource agent.

The fence agent standard provides commands (such as ``off`` and ``reboot``)
that the cluster can use to fence nodes. As with other resource agent classes,
this allows a layer of abstraction so that Pacemaker doesn't need any knowledge
about specific fencing technologies -- that knowledge is isolated in the agent.

Pacemaker supports two fence agent standards, both inherited from
no-longer-active projects:

* Red Hat Cluster Suite (RHCS) style: These are typically installed in
  ``/usr/sbin`` with names starting with ``fence_``.

* Linux-HA style: These typically have names starting with ``external/``.
  Pacemaker can support these agents using the **fence_legacy** RHCS-style
  agent as a wrapper, *if* support was enabled when Pacemaker was built, which
  requires the ``cluster-glue`` library.

When a Fence Device Can Be Used
###############################

Fencing devices do not actually "run" like most services. Typically, they just
provide an interface for sending commands to an external device.

Additionally, fencing may be initiated by Pacemaker, by other cluster-aware
software such as DRBD or DLM, or manually by an administrator, at any point in
the cluster life cycle, including before any resources have been started.

To accommodate this, Pacemaker does not require the fence device resource to be
"started" in order to be used. Whether a fence device is started or not
determines whether a node runs any recurring monitor for the device, and gives
the node a slight preference for being chosen to execute fencing using that
device.

By default, any node can execute any fencing device. If a fence device is
disabled by setting its ``target-role`` to ``Stopped``, then no node can use
that device. If a location constraint with a negative score prevents a specific
node from "running" a fence device, then that node will never be chosen to
execute fencing using the device. A node may fence itself, but the cluster will
choose that only if no other nodes can do the fencing.

A common configuration scenario is to have one fence device per target node.
In such a case, users often configure anti-location constraints so that
the target node does not monitor its own device.

Limitations of Fencing Resources
################################

Fencing resources have certain limitations that other resource classes don't:

* They may have only one set of meta-attributes and one set of instance
  attributes.
* If :ref:`rules` are used to determine fencing resource options, these
  might be evaluated only when first read, meaning that later changes to the
  rules will have no effect. Therefore, it is better to avoid confusion and not
  use rules at all with fencing resources.

These limitations could be revisited if there is sufficient user demand.

.. index::
   single: fencing; special instance attributes

.. _fencing-attributes:

Special Meta-Attributes for Fencing Resources
#############################################

The table below lists special resource meta-attributes that may be set for any
fencing resource.

.. table:: **Additional Properties of Fencing Resources**

   +----------------------+---------+--------------------+----------------------------------------+
   | Field                | Type    | Default            | Description                            |
   +======================+=========+====================+========================================+
   | provides             | string  |                    | .. index::                             |
   |                      |         |                    |    single: provides                    |
   |                      |         |                    |                                        |
   |                      |         |                    | Any special capability provided by the |
   |                      |         |                    | fence device. Currently, only one such |
   |                      |         |                    | capability is meaningful:              |
   |                      |         |                    | :ref:`unfencing <unfencing>`.          |
   +----------------------+---------+--------------------+----------------------------------------+

Special Instance Attributes for Fencing Resources
#################################################

The table below lists special instance attributes that may be set for any
fencing resource (*not* meta-attributes, even though they are interpreted by
Pacemaker rather than the fence agent). These are also listed in the man page
for ``pacemaker-fenced``.

.. Not_Yet_Implemented:

   +----------------------+---------+--------------------+----------------------------------------+
   | priority             | integer | 0                  | .. index::                             |
   |                      |         |                    |    single: priority                    |
   |                      |         |                    |                                        |
   |                      |         |                    | The priority of the fence device.      |
   |                      |         |                    | Devices are tried in order of highest  |
   |                      |         |                    | priority to lowest.                    |
   +----------------------+---------+--------------------+----------------------------------------+

.. table:: **Additional Properties of Fencing Resources**

   +----------------------+---------+--------------------+----------------------------------------+
   | Field                | Type    | Default            | Description                            |
   +======================+=========+====================+========================================+
   | stonith-timeout      | time    |                    | .. index::                             |
   |                      |         |                    |    single: stonith-timeout             |
   |                      |         |                    |                                        |
   |                      |         |                    | This is not used by Pacemaker (see the |
   |                      |         |                    | ``pcmk_reboot_timeout``,               |
   |                      |         |                    | ``pcmk_off_timeout``, etc. properties  |
   |                      |         |                    | instead), but it may be used by        |
   |                      |         |                    | Linux-HA fence agents.                 |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_host_map        | string  |                    | .. index::                             |
   |                      |         |                    |    single: pcmk_host_map               |
   |                      |         |                    |                                        |
   |                      |         |                    | A mapping of host names to ports       |
   |                      |         |                    | numbers for devices that do not        |
   |                      |         |                    | support host names.                    |
   |                      |         |                    |                                        |
   |                      |         |                    | Example: ``node1:1;node2:2,3`` tells   |
   |                      |         |                    | the cluster to use port 1 for          |
   |                      |         |                    | ``node1`` and ports 2 and 3 for        |
   |                      |         |                    | ``node2``. If ``pcmk_host_check`` is   |
   |                      |         |                    | explicitly set to ``static-list``,     |
   |                      |         |                    | either this or ``pcmk_host_list`` must |
   |                      |         |                    | be set.                                |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_host_list       | string  |                    | .. index::                             |
   |                      |         |                    |    single: pcmk_host_list              |
   |                      |         |                    |                                        |
   |                      |         |                    | A list of machines controlled by this  |
   |                      |         |                    | device. If ``pcmk_host_check`` is      |
   |                      |         |                    | explicitly set to ``static-list``,     |
   |                      |         |                    | either this or ``pcmk_host_map`` must  |
   |                      |         |                    | be set.                                |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_host_check      | string  | Value appropriate  | .. index::                             |
   |                      |         | to other           |    single: pcmk_host_check             |
   |                      |         | parameters (see    |                                        |
   |                      |         | "Default Check     | The method Pacemaker should use to     |
   |                      |         | Type" below)       | determine which nodes can be targeted  |
   |                      |         |                    | by this device. Allowed values:        |
   |                      |         |                    |                                        |
   |                      |         |                    | * ``static-list:`` targets are listed  |
   |                      |         |                    |   in the ``pcmk_host_list`` or         |
   |                      |         |                    |   ``pcmk_host_map`` attribute          |
   |                      |         |                    | * ``dynamic-list:`` query the device   |
   |                      |         |                    |   via the agent's ``list`` action      |
   |                      |         |                    | * ``status:`` query the device via the |
   |                      |         |                    |   agent's ``status`` action            |
   |                      |         |                    | * ``none:`` assume the device can      |
   |                      |         |                    |   fence any node                       |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_delay_max       | time    | 0s                 | .. index::                             |
   |                      |         |                    |    single: pcmk_delay_max              |
   |                      |         |                    |                                        |
   |                      |         |                    | Enable a delay of no more than the     |
   |                      |         |                    | time specified before executing        |
   |                      |         |                    | fencing actions. Pacemaker derives the |
   |                      |         |                    | overall delay by taking the value of   |
   |                      |         |                    | pcmk_delay_base and adding a random    |
   |                      |         |                    | delay value such that the sum is kept  |
   |                      |         |                    | below this maximum. This is sometimes  |
   |                      |         |                    | used in two-node clusters to ensure    |
   |                      |         |                    | that the nodes don't fence each other  |
   |                      |         |                    | at the same time.                      |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_delay_base      | time    | 0s                 | .. index::                             |
   |                      |         |                    |    single: pcmk_delay_base             |
   |                      |         |                    |                                        |
   |                      |         |                    | Enable a static delay before executing |
   |                      |         |                    | fencing actions. This can be used, for |
   |                      |         |                    | example, in two-node clusters to       |
   |                      |         |                    | ensure that the nodes don't fence each |
   |                      |         |                    | other, by having separate fencing      |
   |                      |         |                    | resources with different values. The   |
   |                      |         |                    | node that is fenced with the shorter   |
   |                      |         |                    | delay will lose a fencing race. The    |
   |                      |         |                    | overall delay introduced by pacemaker  |
   |                      |         |                    | is derived from this value plus a      |
   |                      |         |                    | random delay such that the sum is kept |
   |                      |         |                    | below the maximum delay. Set to eg.    |
   |                      |         |                    | node1:1s;node2:5 to set different      |
   |                      |         |                    | value per node.                        |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_action_limit    | integer | 1                  | .. index::                             |
   |                      |         |                    |    single: pcmk_action_limit           |
   |                      |         |                    |                                        |
   |                      |         |                    | The maximum number of actions that can |
   |                      |         |                    | be performed in parallel on this       |
   |                      |         |                    | device. A value of -1 means unlimited. |
   |                      |         |                    | Node fencing actions initiated by the  |
   |                      |         |                    | cluster (as opposed to an administrator|
   |                      |         |                    | running the ``stonith_admin`` tool or  |
   |                      |         |                    | the fencer running recurring device    |
   |                      |         |                    | monitors and ``status`` and ``list``   |
   |                      |         |                    | commands) are additionally subject to  |
   |                      |         |                    | the ``concurrent-fencing`` cluster     |
   |                      |         |                    | property.                              |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_host_argument   | string  | ``port`` otherwise | .. index::                             |
   |                      |         | ``plug`` if        |    single: pcmk_host_argument          |
   |                      |         | supported          |                                        |
   |                      |         | according to the   | *Advanced use only.* Which parameter   |
   |                      |         | metadata of the    | should be supplied to the fence agent  |
   |                      |         | fence agent        | to identify the node to be fenced.     |
   |                      |         |                    | Some devices support neither the       |
   |                      |         |                    | standard ``plug`` nor the deprecated   |
   |                      |         |                    | ``port`` parameter, or may provide     |
   |                      |         |                    | additional ones. Use this to specify   |
   |                      |         |                    | an alternate, device-specific          |
   |                      |         |                    | parameter. A value of ``none`` tells   |
   |                      |         |                    | the cluster not to supply any          |
   |                      |         |                    | additional parameters.                 |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_reboot_action   | string  | reboot             | .. index::                             |
   |                      |         |                    |    single: pcmk_reboot_action          |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* The command to    |
   |                      |         |                    | send to the resource agent in order to |
   |                      |         |                    | reboot a node. Some devices do not     |
   |                      |         |                    | support the standard commands or may   |
   |                      |         |                    | provide additional ones. Use this to   |
   |                      |         |                    | specify an alternate, device-specific  |
   |                      |         |                    | command.                               |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_reboot_timeout  | time    | 60s                | .. index::                             |
   |                      |         |                    |    single: pcmk_reboot_timeout         |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* Specify an        |
   |                      |         |                    | alternate timeout to use for           |
   |                      |         |                    | ``reboot`` actions instead of the      |
   |                      |         |                    | value of ``stonith-timeout``. Some     |
   |                      |         |                    | devices need much more or less time to |
   |                      |         |                    | complete than normal. Use this to      |
   |                      |         |                    | specify an alternate, device-specific  |
   |                      |         |                    | timeout.                               |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_reboot_retries  | integer | 2                  | .. index::                             |
   |                      |         |                    |    single: pcmk_reboot_retries         |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* The maximum       |
   |                      |         |                    | number of times to retry the           |
   |                      |         |                    | ``reboot`` command within the timeout  |
   |                      |         |                    | period. Some devices do not support    |
   |                      |         |                    | multiple connections, and operations   |
   |                      |         |                    | may fail if the device is busy with    |
   |                      |         |                    | another task, so Pacemaker will        |
   |                      |         |                    | automatically retry the operation, if  |
   |                      |         |                    | there is time remaining. Use this      |
   |                      |         |                    | option to alter the number of times    |
   |                      |         |                    | Pacemaker retries before giving up.    |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_off_action      | string  | off                | .. index::                             |
   |                      |         |                    |    single: pcmk_off_action             |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* The command to    |
   |                      |         |                    | send to the resource agent in order to |
   |                      |         |                    | shut down a node. Some devices do not  |
   |                      |         |                    | support the standard commands or may   |
   |                      |         |                    | provide additional ones. Use this to   |
   |                      |         |                    | specify an alternate, device-specific  |
   |                      |         |                    | command.                               |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_off_timeout     | time    | 60s                | .. index::                             |
   |                      |         |                    |    single: pcmk_off_timeout            |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* Specify an        |
   |                      |         |                    | alternate timeout to use for           |
   |                      |         |                    | ``off`` actions instead of the         |
   |                      |         |                    | value of ``stonith-timeout``. Some     |
   |                      |         |                    | devices need much more or less time to |
   |                      |         |                    | complete than normal. Use this to      |
   |                      |         |                    | specify an alternate, device-specific  |
   |                      |         |                    | timeout.                               |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_off_retries     | integer | 2                  | .. index::                             |
   |                      |         |                    |    single: pcmk_off_retries            |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* The maximum       |
   |                      |         |                    | number of times to retry the           |
   |                      |         |                    | ``off`` command within the timeout     |
   |                      |         |                    | period. Some devices do not support    |
   |                      |         |                    | multiple connections, and operations   |
   |                      |         |                    | may fail if the device is busy with    |
   |                      |         |                    | another task, so Pacemaker will        |
   |                      |         |                    | automatically retry the operation, if  |
   |                      |         |                    | there is time remaining. Use this      |
   |                      |         |                    | option to alter the number of times    |
   |                      |         |                    | Pacemaker retries before giving up.    |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_list_action     | string  | list               | .. index::                             |
   |                      |         |                    |    single: pcmk_list_action            |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* The command to    |
   |                      |         |                    | send to the resource agent in order to |
   |                      |         |                    | list nodes. Some devices do not        |
   |                      |         |                    | support the standard commands or may   |
   |                      |         |                    | provide additional ones. Use this to   |
   |                      |         |                    | specify an alternate, device-specific  |
   |                      |         |                    | command.                               |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_list_timeout    | time    | 60s                | .. index::                             |
   |                      |         |                    |    single: pcmk_list_timeout           |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* Specify an        |
   |                      |         |                    | alternate timeout to use for           |
   |                      |         |                    | ``list`` actions instead of the        |
   |                      |         |                    | value of ``stonith-timeout``. Some     |
   |                      |         |                    | devices need much more or less time to |
   |                      |         |                    | complete than normal. Use this to      |
   |                      |         |                    | specify an alternate, device-specific  |
   |                      |         |                    | timeout.                               |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_list_retries    | integer | 2                  | .. index::                             |
   |                      |         |                    |    single: pcmk_list_retries           |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* The maximum       |
   |                      |         |                    | number of times to retry the           |
   |                      |         |                    | ``list`` command within the timeout    |
   |                      |         |                    | period. Some devices do not support    |
   |                      |         |                    | multiple connections, and operations   |
   |                      |         |                    | may fail if the device is busy with    |
   |                      |         |                    | another task, so Pacemaker will        |
   |                      |         |                    | automatically retry the operation, if  |
   |                      |         |                    | there is time remaining. Use this      |
   |                      |         |                    | option to alter the number of times    |
   |                      |         |                    | Pacemaker retries before giving up.    |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_monitor_action  | string  | monitor            | .. index::                             |
   |                      |         |                    |    single: pcmk_monitor_action         |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* The command to    |
   |                      |         |                    | send to the resource agent in order to |
   |                      |         |                    | report extended status. Some devices do|
   |                      |         |                    | not support the standard commands or   |
   |                      |         |                    | may provide additional ones. Use this  |
   |                      |         |                    | to specify an alternate,               |
   |                      |         |                    | device-specific command.               |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_monitor_timeout | time    | 60s                | .. index::                             |
   |                      |         |                    |    single: pcmk_monitor_timeout        |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* Specify an        |
   |                      |         |                    | alternate timeout to use for           |
   |                      |         |                    | ``monitor`` actions instead of the     |
   |                      |         |                    | value of ``stonith-timeout``. Some     |
   |                      |         |                    | devices need much more or less time to |
   |                      |         |                    | complete than normal. Use this to      |
   |                      |         |                    | specify an alternate, device-specific  |
   |                      |         |                    | timeout.                               |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_monitor_retries | integer | 2                  | .. index::                             |
   |                      |         |                    |    single: pcmk_monitor_retries        |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* The maximum       |
   |                      |         |                    | number of times to retry the           |
   |                      |         |                    | ``monitor`` command within the timeout |
   |                      |         |                    | period. Some devices do not support    |
   |                      |         |                    | multiple connections, and operations   |
   |                      |         |                    | may fail if the device is busy with    |
   |                      |         |                    | another task, so Pacemaker will        |
   |                      |         |                    | automatically retry the operation, if  |
   |                      |         |                    | there is time remaining. Use this      |
   |                      |         |                    | option to alter the number of times    |
   |                      |         |                    | Pacemaker retries before giving up.    |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_status_action   | string  | status             | .. index::                             |
   |                      |         |                    |    single: pcmk_status_action          |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* The command to    |
   |                      |         |                    | send to the resource agent in order to |
   |                      |         |                    | report status. Some devices do         |
   |                      |         |                    | not support the standard commands or   |
   |                      |         |                    | may provide additional ones. Use this  |
   |                      |         |                    | to specify an alternate,               |
   |                      |         |                    | device-specific command.               |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_status_timeout  | time    | 60s                | .. index::                             |
   |                      |         |                    |    single: pcmk_status_timeout         |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* Specify an        |
   |                      |         |                    | alternate timeout to use for           |
   |                      |         |                    | ``status`` actions instead of the      |
   |                      |         |                    | value of ``stonith-timeout``. Some     |
   |                      |         |                    | devices need much more or less time to |
   |                      |         |                    | complete than normal. Use this to      |
   |                      |         |                    | specify an alternate, device-specific  |
   |                      |         |                    | timeout.                               |
   +----------------------+---------+--------------------+----------------------------------------+
   | pcmk_status_retries  | integer | 2                  | .. index::                             |
   |                      |         |                    |    single: pcmk_status_retries         |
   |                      |         |                    |                                        |
   |                      |         |                    | *Advanced use only.* The maximum       |
   |                      |         |                    | number of times to retry the           |
   |                      |         |                    | ``status`` command within the timeout  |
   |                      |         |                    | period. Some devices do not support    |
   |                      |         |                    | multiple connections, and operations   |
   |                      |         |                    | may fail if the device is busy with    |
   |                      |         |                    | another task, so Pacemaker will        |
   |                      |         |                    | automatically retry the operation, if  |
   |                      |         |                    | there is time remaining. Use this      |
   |                      |         |                    | option to alter the number of times    |
   |                      |         |                    | Pacemaker retries before giving up.    |
   +----------------------+---------+--------------------+----------------------------------------+

Default Check Type
##################

If the user does not explicitly configure ``pcmk_host_check`` for a fence
device, a default value appropriate to other configured parameters will be
used:

* If either ``pcmk_host_list`` or ``pcmk_host_map`` is configured,
  ``static-list`` will be used;
* otherwise, if the fence device supports the ``list`` action, and the first
  attempt at using ``list`` succeeds, ``dynamic-list`` will be used;
* otherwise, if the fence device supports the ``status`` action, ``status``
  will be used;
* otherwise, ``none`` will be used.

.. index::
   single: unfencing
   single: fencing; unfencing

.. _unfencing:

Unfencing
#########

With fabric fencing (such as cutting network or shared disk access rather than
power), it is expected that the cluster will fence the node, and then a system
administrator must manually investigate what went wrong, correct any issues
found, then reboot (or restart the cluster services on) the node.

Once the node reboots and rejoins the cluster, some fabric fencing devices
require an explicit command to restore the node's access. This capability is
called *unfencing* and is typically implemented as the fence agent's ``on``
command.

If any cluster resource has ``requires`` set to ``unfencing``, then that
resource will not be probed or started on a node until that node has been
unfenced.

Fencing and Quorum
##################

In general, a cluster partition may execute fencing only if the partition has
quorum, and the ``stonith-enabled`` cluster property is set to true. However,
there are exceptions:

* The requirements apply only to fencing initiated by Pacemaker. If an
  administrator initiates fencing using the ``stonith_admin`` command, or an
  external application such as DLM initiates fencing using Pacemaker's C API,
  the requirements do not apply.

* A cluster partition without quorum is allowed to fence any active member of
  that partition. As a corollary, this allows a ``no-quorum-policy`` of
  ``suicide`` to work.

* If the ``no-quorum-policy`` cluster property is set to ``ignore``, then
  quorum is not required to execute fencing of any node.

Fencing Timeouts
################

Fencing timeouts are complicated, since a single fencing operation can involve
many steps, each of which may have a separate timeout.

Fencing may be initiated in one of several ways:

* An administrator may initiate fencing using the ``stonith_admin`` tool,
  which has a ``--timeout`` option (defaulting to 2 minutes) that will be used
  as the fence operation timeout.

* An external application such as DLM may initiate fencing using the Pacemaker
  C API. The application will specify the fence operation timeout in this case,
  which might or might not be configurable by the user.

* The cluster may initiate fencing itself. In this case, the
  ``stonith-timeout`` cluster property (defaulting to 1 minute) will be used as
  the fence operation timeout.

However fencing is initiated, the initiator contacts Pacemaker's fencer
(``pacemaker-fenced``) to request fencing. This connection and request has its
own timeout, separate from the fencing operation timeout, but usually happens
very quickly.

The fencer will contact all fencers in the cluster to ask what devices they
have available to fence the target node. The fence operation timeout will be
used as the timeout for each of these queries.

Once a fencing device has been selected, the fencer will check whether any
action-specific timeout has been configured for the device, to use instead of
the fence operation timeout. For example, if ``stonith-timeout`` is 60 seconds,
but the fencing device has ``pcmk_reboot_timeout`` configured as 90 seconds,
then a timeout of 90 seconds will be used for reboot actions using that device.

A device may have retries configured, in which case the timeout applies across
all attempts. For example, if a device has ``pcmk_reboot_retries`` configured
as 2, and the first reboot attempt fails, the second attempt will only have
whatever time is remaining in the action timeout after subtracting how much
time the first attempt used. This means that if the first attempt fails due to
using the entire timeout, no further attempts will be made. There is currently
no way to configure a per-attempt timeout.

If more than one device is required to fence a target, whether due to failure
of the first device or a fencing topology with multiple devices configured for
the target, each device will have its own separate action timeout.

For all of the above timeouts, the fencer will generally multiply the
configured value by 1.2 to get an actual value to use, to account for time
needed by the fencer's own processing.

Separate from the fencer's timeouts, some fence agents have internal timeouts
for individual steps of their fencing process. These agents often have
parameters to configure these timeouts, such as ``login-timeout``,
``shell-timeout``, or ``power-timeout``. Many such agents also have a
``disable-timeout`` parameter to ignore their internal timeouts and just let
Pacemaker handle the timeout. This causes a difference in retry behavior.
If ``disable-timeout`` is not set, and the agent hits one of its internal
timeouts, it will report that as a failure to Pacemaker, which can then retry.
If ``disable-timeout`` is set, and Pacemaker hits a timeout for the agent, then
there will be no time remaining, and no retry will be done.

Fence Devices Dependent on Other Resources
##########################################

In some cases, a fence device may require some other cluster resource (such as
an IP address) to be active in order to function properly.

This is obviously undesirable in general: fencing may be required when the
depended-on resource is not active, or fencing may be required because the node
running the depended-on resource is no longer responding.

However, this may be acceptable under certain conditions:

* The dependent fence device should not be able to target any node that is
  allowed to run the depended-on resource.

* The depended-on resource should not be disabled during production operation.

* The ``concurrent-fencing`` cluster property should be set to ``true``.
  Otherwise, if both the node running the depended-on resource and some node
  targeted by the dependent fence device need to be fenced, the fencing of the
  node running the depended-on resource might be ordered first, making the
  second fencing impossible and blocking further recovery. With concurrent
  fencing, the dependent fence device might fail at first due to the
  depended-on resource being unavailable, but it will be retried and eventually
  succeed once the resource is brought back up.

Even under those conditions, there is one unlikely problem scenario. The DC
always schedules fencing of itself after any other fencing needed, to avoid
unnecessary repeated DC elections. If the dependent fence device targets the
DC, and both the DC and a different node running the depended-on resource need
to be fenced, the DC fencing will always fail and block further recovery. Note,
however, that losing a DC node entirely causes some other node to become DC and
schedule the fencing, so this is only a risk when a stop or other operation
with ``on-fail`` set to ``fencing`` fails on the DC.

.. index::
   single: fencing; configuration

Configuring Fencing
###################

Higher-level tools can provide simpler interfaces to this process, but using
Pacemaker command-line tools, this is how you could configure a fence device.

#. Find the correct driver:

   .. code-block:: none

      # stonith_admin --list-installed

   .. note::

      You may have to install packages to make fence agents available on your
      host. Searching your available packages for ``fence-`` is usually
      helpful. Ensure the packages providing the fence agents you require are
      installed on every cluster node.

#. Find the required parameters associated with the device
   (replacing ``$AGENT_NAME`` with the name obtained from the previous step):

   .. code-block:: none

      # stonith_admin --metadata --agent $AGENT_NAME

#. Create a file called ``stonith.xml`` containing a primitive resource
   with a class of ``stonith``, a type equal to the agent name obtained earlier,
   and a parameter for each of the values returned in the previous step.

#. If the device does not know how to fence nodes based on their uname,
   you may also need to set the special ``pcmk_host_map`` parameter.  See
   :ref:`fencing-attributes` for details.

#. If the device does not support the ``list`` command, you may also need
   to set the special ``pcmk_host_list`` and/or ``pcmk_host_check``
   parameters.  See :ref:`fencing-attributes` for details.

#. If the device does not expect the victim to be specified with the
   ``port`` parameter, you may also need to set the special
   ``pcmk_host_argument`` parameter. See :ref:`fencing-attributes` for details.

#. Upload it into the CIB using cibadmin:

   .. code-block:: none

      # cibadmin --create --scope resources --xml-file stonith.xml

#. Set ``stonith-enabled`` to true:

   .. code-block:: none

      # crm_attribute --type crm_config --name stonith-enabled --update true

#. Once the stonith resource is running, you can test it by executing the
   following, replacing ``$NODE_NAME`` with the name of the node to fence
   (although you might want to stop the cluster on that machine first):

   .. code-block:: none

      # stonith_admin --reboot $NODE_NAME


Example Fencing Configuration
_____________________________

For this example, we assume we have a cluster node, ``pcmk-1``, whose IPMI
controller is reachable at the IP address 192.0.2.1. The IPMI controller uses
the username ``testuser`` and the password ``abc123``.

#. Looking at what's installed, we may see a variety of available agents:

   .. code-block:: none

      # stonith_admin --list-installed

   .. code-block:: none

      (... some output omitted ...)
      fence_idrac
      fence_ilo3
      fence_ilo4
      fence_ilo5
      fence_imm
      fence_ipmilan
      (... some output omitted ...)

   Perhaps after some reading some man pages and doing some Internet searches,
   we might decide ``fence_ipmilan`` is our best choice.

#. Next, we would check what parameters ``fence_ipmilan`` provides:

   .. code-block:: none

      # stonith_admin --metadata -a fence_ipmilan

   .. code-block:: xml

      <resource-agent name="fence_ipmilan" shortdesc="Fence agent for IPMI">
        <symlink name="fence_ilo3" shortdesc="Fence agent for HP iLO3"/>
        <symlink name="fence_ilo4" shortdesc="Fence agent for HP iLO4"/>
        <symlink name="fence_ilo5" shortdesc="Fence agent for HP iLO5"/>
        <symlink name="fence_imm" shortdesc="Fence agent for IBM Integrated Management Module"/>
        <symlink name="fence_idrac" shortdesc="Fence agent for Dell iDRAC"/>
        <longdesc>fence_ipmilan is an I/O Fencing agentwhich can be used with machines controlled by IPMI.This agent calls support software ipmitool (http://ipmitool.sf.net/). WARNING! This fence agent might report success before the node is powered off. You should use -m/method onoff if your fence device works correctly with that option.</longdesc>
        <vendor-url/>
        <parameters>
          <parameter name="action" unique="0" required="0">
            <getopt mixed="-o, --action=[action]"/>
            <content type="string" default="reboot"/>
            <shortdesc lang="en">Fencing action</shortdesc>
          </parameter>
          <parameter name="auth" unique="0" required="0">
            <getopt mixed="-A, --auth=[auth]"/>
            <content type="select">
              <option value="md5"/>
              <option value="password"/>
              <option value="none"/>
            </content>
            <shortdesc lang="en">IPMI Lan Auth type.</shortdesc>
          </parameter>
          <parameter name="cipher" unique="0" required="0">
            <getopt mixed="-C, --cipher=[cipher]"/>
            <content type="string"/>
            <shortdesc lang="en">Ciphersuite to use (same as ipmitool -C parameter)</shortdesc>
          </parameter>
          <parameter name="hexadecimal_kg" unique="0" required="0">
            <getopt mixed="--hexadecimal-kg=[key]"/>
            <content type="string"/>
            <shortdesc lang="en">Hexadecimal-encoded Kg key for IPMIv2 authentication</shortdesc>
          </parameter>
          <parameter name="ip" unique="0" required="0" obsoletes="ipaddr">
            <getopt mixed="-a, --ip=[ip]"/>
            <content type="string"/>
            <shortdesc lang="en">IP address or hostname of fencing device</shortdesc>
          </parameter>
          <parameter name="ipaddr" unique="0" required="0" deprecated="1">
            <getopt mixed="-a, --ip=[ip]"/>
            <content type="string"/>
            <shortdesc lang="en">IP address or hostname of fencing device</shortdesc>
          </parameter>
          <parameter name="ipport" unique="0" required="0">
            <getopt mixed="-u, --ipport=[port]"/>
            <content type="integer" default="623"/>
            <shortdesc lang="en">TCP/UDP port to use for connection with device</shortdesc>
          </parameter>
          <parameter name="lanplus" unique="0" required="0">
            <getopt mixed="-P, --lanplus"/>
            <content type="boolean" default="0"/>
            <shortdesc lang="en">Use Lanplus to improve security of connection</shortdesc>
          </parameter>
          <parameter name="login" unique="0" required="0" deprecated="1">
            <getopt mixed="-l, --username=[name]"/>
            <content type="string"/>
            <shortdesc lang="en">Login name</shortdesc>
          </parameter>
          <parameter name="method" unique="0" required="0">
            <getopt mixed="-m, --method=[method]"/>
            <content type="select" default="onoff">
              <option value="onoff"/>
              <option value="cycle"/>
            </content>
            <shortdesc lang="en">Method to fence</shortdesc>
          </parameter>
          <parameter name="passwd" unique="0" required="0" deprecated="1">
            <getopt mixed="-p, --password=[password]"/>
            <content type="string"/>
            <shortdesc lang="en">Login password or passphrase</shortdesc>
          </parameter>
          <parameter name="passwd_script" unique="0" required="0" deprecated="1">
            <getopt mixed="-S, --password-script=[script]"/>
            <content type="string"/>
            <shortdesc lang="en">Script to run to retrieve password</shortdesc>
          </parameter>
          <parameter name="password" unique="0" required="0" obsoletes="passwd">
            <getopt mixed="-p, --password=[password]"/>
            <content type="string"/>
            <shortdesc lang="en">Login password or passphrase</shortdesc>
          </parameter>
          <parameter name="password_script" unique="0" required="0" obsoletes="passwd_script">
            <getopt mixed="-S, --password-script=[script]"/>
            <content type="string"/>
            <shortdesc lang="en">Script to run to retrieve password</shortdesc>
          </parameter>
          <parameter name="plug" unique="0" required="0" obsoletes="port">
            <getopt mixed="-n, --plug=[ip]"/>
            <content type="string"/>
            <shortdesc lang="en">IP address or hostname of fencing device (together with --port-as-ip)</shortdesc>
          </parameter>
          <parameter name="port" unique="0" required="0" deprecated="1">
            <getopt mixed="-n, --plug=[ip]"/>
            <content type="string"/>
            <shortdesc lang="en">IP address or hostname of fencing device (together with --port-as-ip)</shortdesc>
          </parameter>
          <parameter name="privlvl" unique="0" required="0">
            <getopt mixed="-L, --privlvl=[level]"/>
            <content type="select" default="administrator">
              <option value="callback"/>
              <option value="user"/>
              <option value="operator"/>
              <option value="administrator"/>
            </content>
            <shortdesc lang="en">Privilege level on IPMI device</shortdesc>
          </parameter>
          <parameter name="target" unique="0" required="0">
            <getopt mixed="--target=[targetaddress]"/>
            <content type="string"/>
            <shortdesc lang="en">Bridge IPMI requests to the remote target address</shortdesc>
          </parameter>
          <parameter name="username" unique="0" required="0" obsoletes="login">
            <getopt mixed="-l, --username=[name]"/>
            <content type="string"/>
            <shortdesc lang="en">Login name</shortdesc>
          </parameter>
          <parameter name="quiet" unique="0" required="0">
            <getopt mixed="-q, --quiet"/>
            <content type="boolean"/>
            <shortdesc lang="en">Disable logging to stderr. Does not affect --verbose or --debug-file or logging to syslog.</shortdesc>
          </parameter>
          <parameter name="verbose" unique="0" required="0">
            <getopt mixed="-v, --verbose"/>
            <content type="boolean"/>
            <shortdesc lang="en">Verbose mode</shortdesc>
          </parameter>
          <parameter name="debug" unique="0" required="0" deprecated="1">
            <getopt mixed="-D, --debug-file=[debugfile]"/>
            <content type="string"/>
            <shortdesc lang="en">Write debug information to given file</shortdesc>
          </parameter>
          <parameter name="debug_file" unique="0" required="0" obsoletes="debug">
            <getopt mixed="-D, --debug-file=[debugfile]"/>
            <content type="string"/>
            <shortdesc lang="en">Write debug information to given file</shortdesc>
          </parameter>
          <parameter name="version" unique="0" required="0">
            <getopt mixed="-V, --version"/>
            <content type="boolean"/>
            <shortdesc lang="en">Display version information and exit</shortdesc>
          </parameter>
          <parameter name="help" unique="0" required="0">
            <getopt mixed="-h, --help"/>
            <content type="boolean"/>
            <shortdesc lang="en">Display help and exit</shortdesc>
          </parameter>
          <parameter name="delay" unique="0" required="0">
            <getopt mixed="--delay=[seconds]"/>
            <content type="second" default="0"/>
            <shortdesc lang="en">Wait X seconds before fencing is started</shortdesc>
          </parameter>
          <parameter name="ipmitool_path" unique="0" required="0">
            <getopt mixed="--ipmitool-path=[path]"/>
            <content type="string" default="/usr/bin/ipmitool"/>
            <shortdesc lang="en">Path to ipmitool binary</shortdesc>
          </parameter>
          <parameter name="login_timeout" unique="0" required="0">
            <getopt mixed="--login-timeout=[seconds]"/>
            <content type="second" default="5"/>
            <shortdesc lang="en">Wait X seconds for cmd prompt after login</shortdesc>
          </parameter>
          <parameter name="port_as_ip" unique="0" required="0">
            <getopt mixed="--port-as-ip"/>
            <content type="boolean"/>
            <shortdesc lang="en">Make "port/plug" to be an alias to IP address</shortdesc>
          </parameter>
          <parameter name="power_timeout" unique="0" required="0">
            <getopt mixed="--power-timeout=[seconds]"/>
            <content type="second" default="20"/>
            <shortdesc lang="en">Test X seconds for status change after ON/OFF</shortdesc>
          </parameter>
          <parameter name="power_wait" unique="0" required="0">
            <getopt mixed="--power-wait=[seconds]"/>
            <content type="second" default="2"/>
            <shortdesc lang="en">Wait X seconds after issuing ON/OFF</shortdesc>
          </parameter>
          <parameter name="shell_timeout" unique="0" required="0">
            <getopt mixed="--shell-timeout=[seconds]"/>
            <content type="second" default="3"/>
            <shortdesc lang="en">Wait X seconds for cmd prompt after issuing command</shortdesc>
          </parameter>
          <parameter name="retry_on" unique="0" required="0">
            <getopt mixed="--retry-on=[attempts]"/>
            <content type="integer" default="1"/>
            <shortdesc lang="en">Count of attempts to retry power on</shortdesc>
          </parameter>
          <parameter name="sudo" unique="0" required="0" deprecated="1">
            <getopt mixed="--use-sudo"/>
            <content type="boolean"/>
            <shortdesc lang="en">Use sudo (without password) when calling 3rd party software</shortdesc>
          </parameter>
          <parameter name="use_sudo" unique="0" required="0" obsoletes="sudo">
            <getopt mixed="--use-sudo"/>
            <content type="boolean"/>
            <shortdesc lang="en">Use sudo (without password) when calling 3rd party software</shortdesc>
          </parameter>
          <parameter name="sudo_path" unique="0" required="0">
            <getopt mixed="--sudo-path=[path]"/>
            <content type="string" default="/usr/bin/sudo"/>
            <shortdesc lang="en">Path to sudo binary</shortdesc>
          </parameter>
        </parameters>
        <actions>
          <action name="on" automatic="0"/>
          <action name="off"/>
          <action name="reboot"/>
          <action name="status"/>
          <action name="monitor"/>
          <action name="metadata"/>
          <action name="manpage"/>
          <action name="validate-all"/>
          <action name="diag"/>
          <action name="stop" timeout="20s"/>
          <action name="start" timeout="20s"/>
        </actions>
      </resource-agent>

   Once we've decided what parameter values we think we need, it is a good idea
   to run the fence agent's status action manually, to verify that our values
   work correctly:

   .. code-block:: none

      # fence_ipmilan --lanplus -a 192.0.2.1 -l testuser -p abc123 -o status

      Chassis Power is on

#. Based on that, we might create a fencing resource configuration like this in
   ``stonith.xml`` (or any file name, just use the same name with ``cibadmin``
   later):

   .. code-block:: xml

      <primitive id="Fencing-pcmk-1" class="stonith" type="fence_ipmilan" >
        <instance_attributes id="Fencing-params" >
          <nvpair id="Fencing-lanplus" name="lanplus" value="1" />
          <nvpair id="Fencing-ip" name="ip" value="192.0.2.1" />
          <nvpair id="Fencing-password" name="password" value="testuser" />
          <nvpair id="Fencing-username" name="username" value="abc123" />
        </instance_attributes>
        <operations >
          <op id="Fencing-monitor-10m" interval="10m" name="monitor" timeout="300s" />
        </operations>
      </primitive>

   .. note::

      Even though the man page shows that the ``action`` parameter is
      supported, we do not provide that in the resource configuration.
      Pacemaker will supply an appropriate action whenever the fence device
      must be used.

#. In this case, we don't need to configure ``pcmk_host_map`` because
   ``fence_ipmilan`` ignores the target node name and instead uses its
   ``ip`` parameter to know how to contact the IPMI controller.

#. We do need to let Pacemaker know which cluster node can be fenced by this
   device, since ``fence_ipmilan`` doesn't support the ``list`` action. Add
   a line like this to the agent's instance attributes:

   .. code-block:: xml

          <nvpair id="Fencing-pcmk_host_list" name="pcmk_host_list" value="pcmk-1" />

#. We don't need to configure ``pcmk_host_argument`` since ``ip`` is all the
   fence agent needs (it ignores the target name).

#. Make the configuration active:

   .. code-block:: none

      # cibadmin --create --scope resources --xml-file stonith.xml

#. Set ``stonith-enabled`` to true (this only has to be done once):

   .. code-block:: none

      # crm_attribute --type crm_config --name stonith-enabled --update true

#. Since our cluster is still in testing, we can reboot ``pcmk-1`` without
   bothering anyone, so we'll test our fencing configuration by running this
   from one of the other cluster nodes:

   .. code-block:: none

      # stonith_admin --reboot pcmk-1

   Then we will verify that the node did, in fact, reboot.

We can repeat that process to create a separate fencing resource for each node.

With some other fence device types, a single fencing resource is able to be
used for all nodes. In fact, we could do that with ``fence_ipmilan``, using the
``port-as-ip`` parameter along with ``pcmk_host_map``. Either approach is
fine.

.. index::
   single: fencing; topology
   single: fencing-topology
   single: fencing-level

Fencing Topologies
##################

Pacemaker supports fencing nodes with multiple devices through a feature called
*fencing topologies*. Fencing topologies may be used to provide alternative
devices in case one fails, or to require multiple devices to all be executed
successfully in order to consider the node successfully fenced, or even a
combination of the two.

Create the individual devices as you normally would, then define one or more
``fencing-level`` entries in the ``fencing-topology`` section of the
configuration.

* Each fencing level is attempted in order of ascending ``index``. Allowed
  values are 1 through 9.
* If a device fails, processing terminates for the current level. No further
  devices in that level are exercised, and the next level is attempted instead.
* If the operation succeeds for all the listed devices in a level, the level is
  deemed to have passed.
* The operation is finished when a level has passed (success), or all levels
  have been attempted (failed).
* If the operation failed, the next step is determined by the scheduler and/or
  the controller.

Some possible uses of topologies include:

* Try on-board IPMI, then an intelligent power switch if that fails
* Try fabric fencing of both disk and network, then fall back to power fencing
  if either fails
* Wait up to a certain time for a kernel dump to complete, then cut power to
  the node

.. table:: **Attributes of a fencing-level Element**

   +------------------+-----------------------------------------------------------------------------------------+
   | Attribute        | Description                                                                             |
   +==================+=========================================================================================+
   | id               | .. index::                                                                              |
   |                  |    pair: fencing-level; id                                                              |
   |                  |                                                                                         |
   |                  | A unique name for this element (required)                                               |
   +------------------+-----------------------------------------------------------------------------------------+
   | target           | .. index::                                                                              |
   |                  |    pair: fencing-level; target                                                          |
   |                  |                                                                                         |
   |                  | The name of a single node to which this level applies                                   |
   +------------------+-----------------------------------------------------------------------------------------+
   | target-pattern   | .. index::                                                                              |
   |                  |    pair: fencing-level; target-pattern                                                  |
   |                  |                                                                                         |
   |                  | An extended regular expression (as defined in `POSIX                                    |
   |                  | <https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html#tag_09_04>`_) |
   |                  | matching the names of nodes to which this level applies                                 |
   +------------------+-----------------------------------------------------------------------------------------+
   | target-attribute | .. index::                                                                              |
   |                  |    pair: fencing-level; target-attribute                                                |
   |                  |                                                                                         |
   |                  | The name of a node attribute that is set (to ``target-value``) for nodes to which this  |
   |                  | level applies                                                                           |
   +------------------+-----------------------------------------------------------------------------------------+
   | target-value     | .. index::                                                                              |
   |                  |    pair: fencing-level; target-value                                                    |
   |                  |                                                                                         |
   |                  | The node attribute value (of ``target-attribute``) that is set for nodes to which this  |
   |                  | level applies                                                                           |
   +------------------+-----------------------------------------------------------------------------------------+
   | index            | .. index::                                                                              |
   |                  |    pair: fencing-level; index                                                           |
   |                  |                                                                                         |
   |                  | The order in which to attempt the levels. Levels are attempted in ascending order       |
   |                  | *until one succeeds*. Valid values are 1 through 9.                                     |
   +------------------+-----------------------------------------------------------------------------------------+
   | devices          | .. index::                                                                              |
   |                  |    pair: fencing-level; devices                                                         |
   |                  |                                                                                         |
   |                  | A comma-separated list of devices that must all be tried for this level                 |
   +------------------+-----------------------------------------------------------------------------------------+

.. note:: **Fencing topology with different devices for different nodes**

   .. code-block:: xml

      <cib crm_feature_set="3.6.0" validate-with="pacemaker-3.5" admin_epoch="1" epoch="0" num_updates="0">
        <configuration>
          ...
          <fencing-topology>
            <!-- For pcmk-1, try poison-pill and fail back to power -->
            <fencing-level id="f-p1.1" target="pcmk-1" index="1" devices="poison-pill"/>
            <fencing-level id="f-p1.2" target="pcmk-1" index="2" devices="power"/>
      
            <!-- For pcmk-2, try disk and network, and fail back to power -->
            <fencing-level id="f-p2.1" target="pcmk-2" index="1" devices="disk,network"/>
            <fencing-level id="f-p2.2" target="pcmk-2" index="2" devices="power"/>
          </fencing-topology>
          ...
        <configuration>
        <status/>
      </cib>

Example Dual-Layer, Dual-Device Fencing Topologies
__________________________________________________

The following example illustrates an advanced use of ``fencing-topology`` in a
cluster with the following properties:

* 2 nodes (prod-mysql1 and prod-mysql2)
* the nodes have IPMI controllers reachable at 192.0.2.1 and 192.0.2.2
* the nodes each have two independent Power Supply Units (PSUs) connected to
  two independent Power Distribution Units (PDUs) reachable at 198.51.100.1
  (port 10 and port 11) and 203.0.113.1 (port 10 and port 11)
* fencing via the IPMI controller uses the ``fence_ipmilan`` agent (1 fence device
  per controller, with each device targeting a separate node)
* fencing via the PDUs uses the ``fence_apc_snmp`` agent (1 fence device per
  PDU, with both devices targeting both nodes)
* a random delay is used to lessen the chance of a "death match"
* fencing topology is set to try IPMI fencing first then dual PDU fencing if
  that fails

In a node failure scenario, Pacemaker will first select ``fence_ipmilan`` to
try to kill the faulty node. Using the fencing topology, if that method fails,
it will then move on to selecting ``fence_apc_snmp`` twice (once for the first
PDU, then again for the second PDU).

The fence action is considered successful only if both PDUs report the required
status. If any of them fails, fencing loops back to the first fencing method,
``fence_ipmilan``, and so on, until the node is fenced or the fencing action is
cancelled.

.. note:: **First fencing method: single IPMI device per target**

   Each cluster node has it own dedicated IPMI controller that can be contacted
   for fencing using the following primitives:

   .. code-block:: xml

      <primitive class="stonith" id="fence_prod-mysql1_ipmi" type="fence_ipmilan">
        <instance_attributes id="fence_prod-mysql1_ipmi-instance_attributes">
          <nvpair id="fence_prod-mysql1_ipmi-instance_attributes-ipaddr" name="ipaddr" value="192.0.2.1"/>
          <nvpair id="fence_prod-mysql1_ipmi-instance_attributes-login" name="login" value="fencing"/>
          <nvpair id="fence_prod-mysql1_ipmi-instance_attributes-passwd" name="passwd" value="finishme"/>
          <nvpair id="fence_prod-mysql1_ipmi-instance_attributes-lanplus" name="lanplus" value="true"/>
          <nvpair id="fence_prod-mysql1_ipmi-instance_attributes-pcmk_host_list" name="pcmk_host_list" value="prod-mysql1"/>
          <nvpair id="fence_prod-mysql1_ipmi-instance_attributes-pcmk_delay_max" name="pcmk_delay_max" value="8s"/>
        </instance_attributes>
      </primitive>
      <primitive class="stonith" id="fence_prod-mysql2_ipmi" type="fence_ipmilan">
        <instance_attributes id="fence_prod-mysql2_ipmi-instance_attributes">
          <nvpair id="fence_prod-mysql2_ipmi-instance_attributes-ipaddr" name="ipaddr" value="192.0.2.2"/>
          <nvpair id="fence_prod-mysql2_ipmi-instance_attributes-login" name="login" value="fencing"/>
          <nvpair id="fence_prod-mysql2_ipmi-instance_attributes-passwd" name="passwd" value="finishme"/>
          <nvpair id="fence_prod-mysql2_ipmi-instance_attributes-lanplus" name="lanplus" value="true"/>
          <nvpair id="fence_prod-mysql2_ipmi-instance_attributes-pcmk_host_list" name="pcmk_host_list" value="prod-mysql2"/>
          <nvpair id="fence_prod-mysql2_ipmi-instance_attributes-pcmk_delay_max" name="pcmk_delay_max" value="8s"/>
        </instance_attributes>
      </primitive>

.. note:: **Second fencing method: dual PDU devices**

   Each cluster node also has 2 distinct power supplies controlled by 2
   distinct PDUs:

   * Node 1: PDU 1 port 10 and PDU 2 port 10
   * Node 2: PDU 1 port 11 and PDU 2 port 11

   The matching fencing agents are configured as follows:

   .. code-block:: xml

      <primitive class="stonith" id="fence_apc1" type="fence_apc_snmp">
        <instance_attributes id="fence_apc1-instance_attributes">
          <nvpair id="fence_apc1-instance_attributes-ipaddr" name="ipaddr" value="198.51.100.1"/>
          <nvpair id="fence_apc1-instance_attributes-login" name="login" value="fencing"/>
          <nvpair id="fence_apc1-instance_attributes-passwd" name="passwd" value="fencing"/>
          <nvpair id="fence_apc1-instance_attributes-pcmk_host_list"
             name="pcmk_host_map" value="prod-mysql1:10;prod-mysql2:11"/>
          <nvpair id="fence_apc1-instance_attributes-pcmk_delay_max" name="pcmk_delay_max" value="8s"/>
        </instance_attributes>
      </primitive>
      <primitive class="stonith" id="fence_apc2" type="fence_apc_snmp">
        <instance_attributes id="fence_apc2-instance_attributes">
          <nvpair id="fence_apc2-instance_attributes-ipaddr" name="ipaddr" value="203.0.113.1"/>
          <nvpair id="fence_apc2-instance_attributes-login" name="login" value="fencing"/>
          <nvpair id="fence_apc2-instance_attributes-passwd" name="passwd" value="fencing"/>
          <nvpair id="fence_apc2-instance_attributes-pcmk_host_list"
             name="pcmk_host_map" value="prod-mysql1:10;prod-mysql2:11"/>
          <nvpair id="fence_apc2-instance_attributes-pcmk_delay_max" name="pcmk_delay_max" value="8s"/>
        </instance_attributes>
      </primitive>

.. note:: **Fencing topology**

   Now that all the fencing resources are defined, it's time to create the
   right topology. We want to first fence using IPMI and if that does not work,
   fence both PDUs to effectively and surely kill the node.

   .. code-block:: xml

      <fencing-topology>
        <fencing-level id="level-1-1" target="prod-mysql1" index="1" devices="fence_prod-mysql1_ipmi" />
        <fencing-level id="level-1-2" target="prod-mysql1" index="2" devices="fence_apc1,fence_apc2"  />
        <fencing-level id="level-2-1" target="prod-mysql2" index="1" devices="fence_prod-mysql2_ipmi" />
        <fencing-level id="level-2-2" target="prod-mysql2" index="2" devices="fence_apc1,fence_apc2"  />
      </fencing-topology>

   In ``fencing-topology``, the lowest ``index`` value for a target determines
   its first fencing method.

Remapping Reboots
#################

When the cluster needs to reboot a node, whether because ``stonith-action`` is
``reboot`` or because a reboot was requested externally (such as by
``stonith_admin --reboot``), it will remap that to other commands in two cases:

* If the chosen fencing device does not support the ``reboot`` command, the
  cluster will ask it to perform ``off`` instead.

* If a fencing topology level with multiple devices must be executed, the
  cluster will ask all the devices to perform ``off``, then ask the devices to
  perform ``on``.

To understand the second case, consider the example of a node with redundant
power supplies connected to intelligent power switches. Rebooting one switch
and then the other would have no effect on the node. Turning both switches off,
and then on, actually reboots the node.

In such a case, the fencing operation will be treated as successful as long as
the ``off`` commands succeed, because then it is safe for the cluster to
recover any resources that were on the node. Timeouts and errors in the ``on``
phase will be logged but ignored.

When a reboot operation is remapped, any action-specific timeout for the
remapped action will be used (for example, ``pcmk_off_timeout`` will be used
when executing the ``off`` command, not ``pcmk_reboot_timeout``).
