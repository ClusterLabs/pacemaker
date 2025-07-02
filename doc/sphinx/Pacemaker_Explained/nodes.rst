.. index::
   single: node

Nodes
-----

Pacemaker supports two basic types of nodes: *cluster nodes* and *Pacemaker
Remote nodes*.

.. index::
   single: node; cluster node

Cluster nodes
_____________

Cluster nodes run Corosync and all Pacemaker components. They may run cluster
resources, run all Pacemaker command-line tools, execute fencing actions, count
toward cluster quorum, and serve as the cluster's Designated Controller (DC).

Every cluster must have at least one cluster node. Scalability is limited by
the cluster layer to around 32 cluster nodes.

Host Clock Considerations
#########################

In general, Pacemaker does not rely on time or time zones being synchronized
across nodes. However, if the configuration uses date/time-based :ref:`rules
<rules>`, synchronization is a good idea, otherwise the rules will evaluate
differently depending on which node is the Designated Controller (DC). Also,
synchronization is greatly helpful when comparing logs across multiple nodes
for problem investigation.

If a node's clock jumps forward, you may see relatively minor issues such as
various timeouts suddenly being considered expired.

If a node's clock jumps backward, more serious problems may occur, so this
should be avoided. If the host clock is adjusted at boot, and Pacemaker is
enabled at boot, Pacemaker's start should be ordered after the clock
adjustment. When run under systemd, Pacemaker will automatically order itself
after ``time-sync.target``. However, depending on the local setup, you may need
to enable an additional service (for example, ``chronyd-wait.service``) for
that to be effective, or write your own workaround (for example, see the
discussion on
`systemd issue#5097 <https://github.com/systemd/systemd/issues/5097>`_.


.. _pacemaker_remote:

.. index::
   pair: node; Pacemaker Remote

Pacemaker Remote nodes
______________________

Pacemaker Remote nodes do not run Corosync or the usual Pacemaker components.
Instead, they run only the *remote executor* (``pacemaker-remoted``), which
waits for Pacemaker on a cluster node to give it instructions.

They may run cluster resources and most command-line tools, but cannot perform
other functions of full cluster nodes such as fencing execution, quorum voting,
or DC eligibility.

There is no hard limit on the number of Pacemaker Remote nodes.

.. NOTE::

    *Remote* in this document has nothing to do with physical proximity and
    instead refers to the node not being a member of the underlying Corosync
    cluster. Pacemaker Remote nodes are subject to the same latency
    requirements as cluster nodes, which means they are typically in the same
    data center.

There are three types of Pacemaker Remote nodes:

* A *remote node* boots outside Pacemaker control, and is typically a physical
  host. The connection to the remote node is managed as a :ref:`special type of
  resource <remote_nodes>` configured by the user.

* A *guest node* is a virtual machine or container configured to run
  Pacemaker's remote executor when launched, and is launched and managed by the
  cluster as a standard resource configured by the user with :ref:`special
  options <guest_nodes>`.

* A *bundle node* is a guest node created for a container that is launched and
  managed by the cluster as part of a :ref:`bundle <s-resource-bundle>`
  resource configured by the user.

.. NOTE::

    It is important to distinguish the various roles a virtual machine can serve
    in Pacemaker clusters:

    * A virtual machine can run the full cluster stack, in which case it is a
      cluster node and is not itself managed by the cluster.
    * A virtual machine can be managed by the cluster as a simple resource,
      without the cluster having any awareness of the services running within
      it. The virtual machine is *opaque* to the cluster.
    * A virtual machine can be a guest node, allowing the cluster to manage
      both the virtual machine and resources running within it. The virtual
      machine is *transparent* to the cluster.

Defining a Node
_______________

Each cluster node will have an entry in the ``nodes`` section containing at
least an ID and a name. A cluster node's ID is defined by the cluster layer
(Corosync).

.. topic:: **Example Corosync cluster node entry**

   .. code-block:: xml

      <node id="101" uname="pcmk-1"/>

Pacemaker Remote nodes are defined by a resource in the ``resources`` section.
Remote nodes and guest nodes may optionally have an entry in the ``nodes``
section, primarily for permanent :ref:`node attributes <node_attributes>`.

Normally, the user should let the cluster populate the ``nodes`` section
automatically.

.. index::
   single: node; name

.. _node_name:

Where Pacemaker Gets the Node Name
##################################

The name that Pacemaker uses for a node in the configuration does not have to
be the same as its local hostname. Pacemaker uses the following for a cluster
node's name, in order of most preferred first:

* The value of ``name`` in the ``nodelist`` section of ``corosync.conf``
  (``nodeid`` must also be explicitly set there in order for Pacemaker to
  associate the name with the node)
* The value of ``ring0_addr`` in the ``nodelist`` section of ``corosync.conf``
* The local hostname (value of ``uname -n``)

A Pacemaker Remote node's name is defined in its resource configuration.

If the cluster is running, the ``crm_node -n`` command will display the local
node's name as used by the cluster.

If a Corosync ``nodelist`` is used, ``crm_node --name-for-id`` with a Corosync
node ID will display the name used by the node with the given Corosync
``nodeid``, for example:

.. code-block:: none

   crm_node --name-for-id 2


.. index::
   single: node; quorum-only
   single: quorum-only node

Quorum-only Nodes
_________________

One popular cluster design uses an even number of cluster nodes (often 2), with
an additional lightweight host that contributes to providing quorum but cannot
run resources.

With Pacemaker, this can be achieved in either of two ways:

* When Corosync is used as the underlying cluster layer, the lightweight host
  can run `qdevice <https://github.com/corosync/corosync-qdevice>`_ instead of
  Corosync and Pacemaker.

* The lightweight host can be configured as a Pacemaker cluster node, and a
  :ref:`location constraint <location-constraint>` can be configured for the
  node with ``score`` set to ``-INFINITY``, ``rsc-pattern`` set to ``.*``, and
  ``resource-discovey`` set to ``never``.


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

.. warning::

   Attribute values with newline or tab characters are currently displayed with
   newlines as ``"\n"`` and tabs as ``"\t"``, when ``crm_attribute`` or
   ``attrd_updater`` query commands use ``--output-as=text`` or leave
   ``--output-as`` unspecified:

   .. code-block:: none

      # crm_attribute -N node1 -n test_attr -v "$(echo -e "a\nb\tc")" -t status
      # crm_attribute -N node1 -n test_attr --query -t status
      scope=status  name=test_attr value=a\nb\tc

   This format is deprecated. In a future release, the values will be displayed
   with literal whitespace characters:

   .. code-block:: none

      # crm_attribute -N node1 -n test_attr --query -t status
      scope=status  name=test_attr value=a
      b	c

   Users should either avoid attribute values with newlines and tabs, or ensure
   that they can handle both formats.

   However, it's best to use ``--output-as=xml`` when parsing attribute values
   from output. Newlines, tabs, and special characters are replaced with XML
   character references that a conforming XML processor can recognize and
   convert to literals *(since 2.1.8)*:

   .. code-block:: none

      # crm_attribute -N node1 -n test_attr --query -t status --output-as=xml
      <pacemaker-result api-version="2.35" request="crm_attribute -N laptop -n test_attr --query -t status --output-as=xml">
        <attribute name="test_attr" value="a&#10;b&#9;c" scope="status"/>
        <status code="0" message="OK"/>
      </pacemaker-result>


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

.. table:: **Node Attributes With Special Significance**
   :class: longtable
   :widths: 30 70

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
   | maintenance                | .. _node_maintenance:                               |
   |                            |                                                     |
   |                            | .. index::                                          |
   |                            |    pair: node attribute; maintenance                |
   |                            |                                                     |
   |                            | If true, the cluster will not start or stop any     |
   |                            | resources on this node. Any resources active on the |
   |                            | node become unmanaged, and any recurring operations |
   |                            | for those resources (except those specifying        |
   |                            | ``role`` as ``Stopped``) will be paused. The        |
   |                            | :ref:`maintenance-mode <maintenance_mode>` cluster  |
   |                            | option, if true, overrides this. If this attribute  |
   |                            | is true, it overrides the                           |
   |                            | :ref:`is-managed <is_managed>` and                  |
   |                            | :ref:`maintenance <rsc_maintenance>`                |
   |                            | meta-attributes of affected resources and           |
   |                            | :ref:`enabled <op_enabled>` meta-attribute for      |
   |                            | affected recurring actions. Pacemaker should not be |
   |                            | restarted on a node that is in single-node          |
   |                            | maintenance mode.                                   |
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
   :widths: 25 75

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
   |            | This indicator is close to unhealthy (whether worsening or   |
   |            | recovering)                                                  |
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

.. note::

   A health attribute may technically be transient or permanent, but generally
   only transient makes sense.

.. note::

   ``red``, ``yellow``, and ``green`` function as aliases for particular
   numeric scores as described later.


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
   :widths: 25 75

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
