Cluster Nodes
-------------

Defining a Cluster Node
_______________________

Each cluster node will have an entry in the ``nodes`` section containing at
least an ID and a name. A cluster node's ID is defined by the cluster layer
(Corosync).

.. topic:: **Example Corosync cluster node entry**

   .. code-block:: xml

      <node id="101" uname="pcmk-1"/>

In normal circumstances, the admin should let the cluster populate this
information automatically from the cluster layer.


.. _node_name:

Where Pacemaker Gets the Node Name
##################################

The name that Pacemaker uses for a node in the configuration does not have to
be the same as its local hostname. Pacemaker uses the following for a Corosync
node's name, in order of most preferred first:

* The value of ``name`` in the ``nodelist`` section of ``corosync.conf``
* The value of ``ring0_addr`` in the ``nodelist`` section of ``corosync.conf``
* The local hostname (value of ``uname -n``)

If the cluster is running, the ``crm_node -n`` command will display the local
node's name as used by the cluster.

If a Corosync ``nodelist`` is used, ``crm_node --name-for-id`` with a Corosync
node ID will display the name used by the node with the given Corosync
``nodeid``, for example:

.. code-block:: none

   crm_node --name-for-id 2


.. index::
   single: node; attribute
   single: node attribute

.. _node_attributes:

Node Attributes
_______________

Pacemaker allows node-specific values to be specified using *node attributes*.
A node attribute has a name, and may have a distinct value for each node.

Node attributes come in two types, *permanent* and *transient*. Permanent node
attributes are kept within the ``node`` entry, and keep their values even if
the cluster restarts on a node. Transient node attributes are kept in the CIB's
``status`` section, and go away when the cluster stops on the node.

While certain node attributes have specific meanings to the cluster, they are
mainly intended to allow administrators and resource agents to track any
information desired.

For example, an administrator might choose to define node attributes for how
much RAM and disk space each node has, which OS each uses, or which server room
rack each node is in.

Users can configure :ref:`rules` that use node attributes to affect where
resources are placed.

Setting and querying node attributes
####################################

Node attributes can be set and queried using the ``crm_attribute`` and
``attrd_updater`` commands, so that the user does not have to deal with XML
configuration directly.

Here is an example command to set a permanent node attribute, and the XML
configuration that would be generated:

.. topic:: **Result of using crm_attribute to specify which kernel pcmk-1 is running**

   .. code-block:: none

      # crm_attribute --type nodes --node pcmk-1 --name kernel --update $(uname -r)

   .. code-block:: xml

      <node id="1" uname="pcmk-1">
         <instance_attributes id="nodes-1-attributes">
           <nvpair id="nodes-1-kernel" name="kernel" value="3.10.0-862.14.4.el7.x86_64"/>
         </instance_attributes>
      </node>

To read back the value that was just set:

.. code-block:: none

   # crm_attribute --type nodes --node pcmk-1 --name kernel --query
   scope=nodes  name=kernel value=3.10.0-862.14.4.el7.x86_64

The ``--type nodes`` indicates that this is a permanent node attribute;
``--type status`` would indicate a transient node attribute.

Special node attributes
#######################

Certain node attributes have special meaning to the cluster.

Node attribute names beginning with ``#`` are considered reserved for these
special attributes. Some special attributes do not start with ``#``, for
historical reasons.

Certain special attributes are set automatically by the cluster, should never
be modified directly, and can be used only within :ref:`rules`; these are
listed under
:ref:`built-in node attributes <node-attribute-expressions-special>`.

For true/false values, the cluster considers a value of "1", "y", "yes", "on",
or "true" (case-insensitively) to be true, "0", "n", "no", "off", "false", or
unset to be false, and anything else to be an error.

.. table:: **Node attributes with special significance**

   +----------------------------+-----------------------------------------------------+
   | Name                       | Description                                         |
   +============================+=====================================================+
   | fail-count-*               | .. index::                                          |
   |                            |    pair: node attribute; fail-count                 |
   |                            |                                                     |
   |                            | Attributes whose names start with                   |
   |                            | ``fail-count-`` are managed by the cluster          |
   |                            | to track how many times particular resource         |
   |                            | operations have failed on this node. These          |
   |                            | should be queried and cleared via the               |
   |                            | ``crm_failcount`` or                                |
   |                            | ``crm_resource --cleanup`` commands rather          |
   |                            | than directly.                                      |
   +----------------------------+-----------------------------------------------------+
   | last-failure-*             | .. index::                                          |
   |                            |    pair: node attribute; last-failure               |
   |                            |                                                     |
   |                            | Attributes whose names start with                   |
   |                            | ``last-failure-`` are managed by the cluster        |
   |                            | to track when particular resource operations        |
   |                            | have most recently failed on this node.             |
   |                            | These should be cleared via the                     |
   |                            | ``crm_failcount`` or                                |
   |                            | ``crm_resource --cleanup`` commands rather          |
   |                            | than directly.                                      |
   +----------------------------+-----------------------------------------------------+
   | maintenance                | .. index::                                          |
   |                            |    pair: node attribute; maintenance                |
   |                            |                                                     |
   |                            | Similar to the ``maintenance-mode``                 |
   |                            | :ref:`cluster option <cluster_options>`, but        |
   |                            | for a single node. If true, resources will          |
   |                            | not be started or stopped on the node,              |
   |                            | resources and individual clone instances            |
   |                            | running on the node will become unmanaged,          |
   |                            | and any recurring operations for those will         |
   |                            | be cancelled.                                       |
   |                            |                                                     |
   |                            | **Warning:** Restarting pacemaker on a node that is |
   |                            | in single-node maintenance mode will likely         |
   |                            | lead to undesirable effects. If                     |
   |                            | ``maintenance`` is set as a transient               |
   |                            | attribute, it will be erased when                   |
   |                            | Pacemaker is stopped, which will                    |
   |                            | immediately take the node out of                    |
   |                            | maintenance mode and likely get it                  |
   |                            | fenced. Even if permanent, if Pacemaker             |
   |                            | is restarted, any resources active on the           |
   |                            | node will have their local history erased           |
   |                            | when the node rejoins, so the cluster               |
   |                            | will no longer consider them running on             |
   |                            | the node and thus will consider them                |
   |                            | managed again, leading them to be started           |
   |                            | elsewhere. This behavior might be                   |
   |                            | improved in a future release.                       |
   +----------------------------+-----------------------------------------------------+
   | probe_complete             | .. index::                                          |
   |                            |    pair: node attribute; probe_complete             |
   |                            |                                                     |
   |                            | This is managed by the cluster to detect            |
   |                            | when nodes need to be reprobed, and should          |
   |                            | never be used directly.                             |
   +----------------------------+-----------------------------------------------------+
   | resource-discovery-enabled | .. index::                                          |
   |                            |    pair: node attribute; resource-discovery-enabled |
   |                            |                                                     |
   |                            | If the node is a remote node, fencing is enabled,   |
   |                            | and this attribute is explicitly set to false       |
   |                            | (unset means true in this case), resource discovery |
   |                            | (probes) will not be done on this node. This is     |
   |                            | highly discouraged; the ``resource-discovery``      |
   |                            | location constraint property is preferred for this  |
   |                            | purpose.                                            |
   +----------------------------+-----------------------------------------------------+
   | shutdown                   | .. index::                                          |
   |                            |    pair: node attribute; shutdown                   |
   |                            |                                                     |
   |                            | This is managed by the cluster to orchestrate the   |
   |                            | shutdown of a node, and should never be used        |
   |                            | directly.                                           |
   +----------------------------+-----------------------------------------------------+
   | site-name                  | .. index::                                          |
   |                            |    pair: node attribute; site-name                  |
   |                            |                                                     |
   |                            | If set, this will be used as the value of the       |
   |                            | ``#site-name`` node attribute used in rules. (If    |
   |                            | not set, the value of the ``cluster-name`` cluster  |
   |                            | option will be used as ``#site-name`` instead.)     |
   +----------------------------+-----------------------------------------------------+
   | standby                    | .. index::                                          |
   |                            |    pair: node attribute; standby                    |
   |                            |                                                     |
   |                            | If true, the node is in standby mode. This is       |
   |                            | typically set and queried via the ``crm_standby``   |
   |                            | command rather than directly.                       |
   +----------------------------+-----------------------------------------------------+
   | terminate                  | .. index::                                          |
   |                            |    pair: node attribute; terminate                  |
   |                            |                                                     |
   |                            | If the value is true or begins with any nonzero     |
   |                            | number, the node will be fenced. This is typically  |
   |                            | set by tools rather than directly.                  |
   +----------------------------+-----------------------------------------------------+
   | #digests-*                 | .. index::                                          |
   |                            |    pair: node attribute; #digests                   |
   |                            |                                                     |
   |                            | Attributes whose names start with ``#digests-`` are |
   |                            | managed by the cluster to detect when               |
   |                            | :ref:`unfencing` needs to be redone, and should     |
   |                            | never be used directly.                             |
   +----------------------------+-----------------------------------------------------+
   | #node-unfenced             | .. index::                                          |
   |                            |    pair: node attribute; #node-unfenced             |
   |                            |                                                     |
   |                            | When the node was last unfenced (as seconds since   |
   |                            | the epoch). This is managed by the cluster and      |
   |                            | should never be used directly.                      |
   +----------------------------+-----------------------------------------------------+

.. index::
   single: node; health

.. _node-health:

Tracking Node Health
____________________

A node may be functioning adequately as far as cluster membership is concerned,
and yet be "unhealthy" in some respect that makes it an undesirable location
for resources. For example, a disk drive may be reporting SMART errors, or the
CPU may be highly loaded.

Pacemaker offers a way to automatically move resources off unhealthy nodes.

.. index::
   single: node attribute; health

Node Health Attributes
######################

Pacemaker will treat any node attribute whose name starts with ``#health`` as
an indicator of node health. Node health attributes may have one of the
following values:

.. table:: **Allowed Values for Node Health Attributes**

   +------------+--------------------------------------------------------------+
   | Value      | Intended significance                                        |
   +============+==============================================================+
   | ``red``    | .. index::                                                   |
   |            |    single: red; node health attribute value                  |
   |            |    single: node attribute; health (red)                      |
   |            |                                                              |
   |            | This indicator is unhealthy                                  |
   +------------+--------------------------------------------------------------+
   | ``yellow`` | .. index::                                                   |
   |            |    single: yellow; node health attribute value               |
   |            |    single: node attribute; health (yellow)                   |
   |            |                                                              |
   |            | This indicator is becoming unhealthy                         |
   +------------+--------------------------------------------------------------+
   | ``green``  | .. index::                                                   |
   |            |    single: green; node health attribute value                |
   |            |    single: node attribute; health (green)                    |
   |            |                                                              |
   |            | This indicator is healthy                                    |
   +------------+--------------------------------------------------------------+
   | *integer*  | .. index::                                                   |
   |            |    single: score; node health attribute value                |
   |            |    single: node attribute; health (score)                    |
   |            |                                                              |
   |            | A numeric score to apply to all resources on this node (0 or |
   |            | positive is healthy, negative is unhealthy)                  |
   +------------+--------------------------------------------------------------+


.. index::
   pair: cluster option; node-health-strategy

Node Health Strategy
####################

Pacemaker assigns a node health score to each node, as the sum of the values of
all its node health attributes. This score will be used as a location
constraint applied to this node for all resources.

The ``node-health-strategy`` cluster option controls how Pacemaker responds to
changes in node health attributes, and how it translates ``red``, ``yellow``,
and ``green`` to scores.

Allowed values are:

.. table:: **Node Health Strategies**

   +----------------+----------------------------------------------------------+
   | Value          | Effect                                                   |
   +================+==========================================================+
   | none           | .. index::                                               |
   |                |    single: node-health-strategy; none                    |
   |                |    single: none; node-health-strategy value              |
   |                |                                                          |
   |                | Do not track node health attributes at all.              |
   +----------------+----------------------------------------------------------+
   | migrate-on-red | .. index::                                               |
   |                |    single: node-health-strategy; migrate-on-red          |
   |                |    single: migrate-on-red; node-health-strategy value    |
   |                |                                                          |
   |                | Assign the value of ``-INFINITY`` to ``red``, and 0 to   |
   |                | ``yellow`` and ``green``. This will cause all resources  |
   |                | to move off the node if any attribute is ``red``.        |
   +----------------+----------------------------------------------------------+
   | only-green     | .. index::                                               |
   |                |    single: node-health-strategy; only-green              |
   |                |    single: only-green; node-health-strategy value        |
   |                |                                                          |
   |                | Assign the value of ``-INFINITY`` to ``red`` and         |
   |                | ``yellow``, and 0 to ``green``. This will cause all      |
   |                | resources to move off the node if any attribute is       |
   |                | ``red`` or ``yellow``.                                   |
   +----------------+----------------------------------------------------------+
   | progressive    | .. index::                                               |
   |                |    single: node-health-strategy; progressive             |
   |                |    single: progressive; node-health-strategy value       |
   |                |                                                          |
   |                | Assign the value of the ``node-health-red`` cluster      |
   |                | option to ``red``, the value of ``node-health-yellow``   |
   |                | to ``yellow``, and the value of ``node-health-green`` to |
   |                | ``green``. Each node is additionally assigned a score of |
   |                | ``node-health-base`` (this allows resources to start     |
   |                | even if some attributes are ``yellow``). This strategy   |
   |                | gives the administrator finer control over how important |
   |                | each value is.                                           |
   +----------------+----------------------------------------------------------+
   | custom         | .. index::                                               |
   |                |    single: node-health-strategy; custom                  |
   |                |    single: custom; node-health-strategy value            |
   |                |                                                          |
   |                | Track node health attributes using the same values as    |
   |                | ``progressive`` for ``red``, ``yellow``, and ``green``,  |
   |                | but do not take them into account. The administrator is  |
   |                | expected to implement a policy by defining :ref:`rules`  |
   |                | referencing node health attributes.                      |
   +----------------+----------------------------------------------------------+


Exempting a Resource from Health Restrictions
#############################################

If you want a resource to be able to run on a node even if its health score
would otherwise prevent it, set the resource's ``allow-unhealthy-nodes``
meta-attribute to ``true`` *(available since 2.1.3)*.

This is particularly useful for node health agents, to allow them to detect
when the node becomes healthy again. If you configure a health agent without
this setting, then the health agent will be banned from an unhealthy node,
and you will have to investigate and clear the health attribute manually once
it is healthy to allow resources on the node again.

If you want the meta-attribute to apply to a clone, it must be set on the clone
itself, not on the resource being cloned.


Configuring Node Health Agents
##############################

Since Pacemaker calculates node health based on node attributes, any method
that sets node attributes may be used to measure node health. The most common
are resource agents and custom daemons.

Pacemaker provides examples that can be used directly or as a basis for custom
code. The ``ocf:pacemaker:HealthCPU``, ``ocf:pacemaker:HealthIOWait``, and
``ocf:pacemaker:HealthSMART`` resource agents set node health attributes based
on CPU and disk status.

To take advantage of this feature, add the resource to your cluster (generally
as a cloned resource with a recurring monitor action, to continually check the
health of all nodes). For example:

.. topic:: Example HealthIOWait resource configuration

   .. code-block:: xml

      <clone id="resHealthIOWait-clone">
        <primitive class="ocf" id="HealthIOWait" provider="pacemaker" type="HealthIOWait">
          <instance_attributes id="resHealthIOWait-instance_attributes">
            <nvpair id="resHealthIOWait-instance_attributes-red_limit" name="red_limit" value="30"/>
            <nvpair id="resHealthIOWait-instance_attributes-yellow_limit" name="yellow_limit" value="10"/>
          </instance_attributes>
          <operations>
            <op id="resHealthIOWait-monitor-interval-5" interval="5" name="monitor" timeout="5"/>
            <op id="resHealthIOWait-start-interval-0s" interval="0s" name="start" timeout="10s"/>
            <op id="resHealthIOWait-stop-interval-0s" interval="0s" name="stop" timeout="10s"/>
          </operations>
        </primitive>
      </clone>

The resource agents use ``attrd_updater`` to set proper status for each node
running this resource, as a node attribute whose name starts with ``#health``
(for ``HealthIOWait``, the node attribute is named ``#health-iowait``).

When a node is no longer faulty, you can force the cluster to make it available
to take resources without waiting for the next monitor, by setting the node
health attribute to green. For example:

.. topic:: **Force node1 to be marked as healthy**

   .. code-block:: none

      # attrd_updater --name "#health-iowait" --update "green" --node "node1"
