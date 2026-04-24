.. _resource:

Resources
---------

.. _s-resource-primitive:

.. index::
   single: resource

A *resource* is a service managed by Pacemaker. The simplest type of resource,
a *primitive*, is described in this chapter. More complex forms, such as groups
and clones, are described in later chapters.

Every primitive has a *resource agent* that provides Pacemaker a standardized
interface for managing the service. This allows Pacemaker to be agnostic about
the services it manages. Pacemaker doesn't need to understand how the service
works because it relies on the resource agent to do the right thing when asked.

Every resource has a *standard* (also called *class*) specifying the interface
that its resource agent follows, and a *type* identifying the specific service
being managed.


.. _s-resource-supported:

.. index::
   single: resource; standard

Resource Standards
##################

Pacemaker can use resource agents complying with these standards, described in
more detail below:

* ocf
* lsb
* systemd
* service
* stonith

Support for some standards is controlled by build options and so might not be
available in any particular build of Pacemaker. The command ``crm_resource
--list-standards`` will show which standards are supported by the local build.

.. index::
   single: resource; OCF
   single: OCF; resources
   single: Open Cluster Framework; resources

Open Cluster Framework
______________________

The Open Cluster Framework (OCF) Resource Agent API is a ClusterLabs
standard for managing services. It is the most preferred since it is
specifically designed for use in a Pacemaker cluster.

OCF agents are scripts that support a variety of actions including ``start``,
``stop``, and ``monitor``. They may accept parameters, making them more
flexible than other standards. The number and purpose of parameters is left to
the agent, which advertises them via the ``meta-data`` action.

Unlike other standards, OCF agents have a *provider* as well as a standard and
type.

For more information, see the "Resource Agents" chapter of *Pacemaker
Administration* and the `OCF standard
<https://github.com/ClusterLabs/OCF-spec/tree/main/ra>`_.


.. _s-resource-supported-systemd:

.. index::
   single: Resource; Systemd
   single: Systemd; resources

Systemd
_______

Most Linux distributions use `Systemd
<http://www.freedesktop.org/wiki/Software/systemd>`_ for system initialization
and service management. *Unit files* specify how to manage services and are
usually provided by the distribution.

Pacemaker can manage systemd units of type service, socket, mount, timer, or
path. Simply create a resource with ``systemd`` as the resource standard and
the unit file name as the resource type. Do *not* run ``systemctl enable`` on
the unit.

.. important::

   Make sure that any systemd services to be controlled by the cluster are
   *not* enabled to start at boot.


.. index::
   single: resource; LSB
   single: LSB; resources
   single: Linux Standard Base; resources

Linux Standard Base
___________________

*LSB* resource agents, also known as `SysV-style
<https://en.wikipedia.org/wiki/Init#SysV-style init scripts>`_, are scripts that
provide start, stop, and status actions for a service.

They are provided by some operating system distributions. If a full path is not
given, they are assumed to be located in a directory specified when your
Pacemaker software was built (usually ``/etc/init.d``).

In order to be used with Pacemaker, they must conform to the `LSB specification
<http://refspecs.linux-foundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/iniscrptact.html>`_
as it relates to init scripts.

.. warning::

   Some LSB scripts do not fully comply with the standard. For details on how
   to check whether your script is LSB-compatible, see the "Resource Agents"
   chapter of `Pacemaker Administration`. Common problems include:

   * Not implementing the ``status`` action
   * Not observing the correct exit status codes
   * Starting a started resource returns an error
   * Stopping a stopped resource returns an error

.. important::

   Make sure the host is *not* configured to start any LSB services at boot
   that will be controlled by the cluster.


.. index::
   single: Resource; System Services
   single: System Service; resources

System Services
_______________

Since there is more than one type of system service (``systemd`` and ``lsb``),
Pacemaker supports a special ``service`` alias which intelligently figures out
which one applies to a given cluster node.

This is particularly useful when the cluster contains a mix of ``systemd`` and
``lsb``.

If the ``service`` standard is specified, Pacemaker will try to find the named
service as an LSB init script, and if none exists, a systemd unit file.


.. index::
   single: Resource; STONITH
   single: STONITH; resources

STONITH
_______

The ``stonith`` standard is used for managing fencing devices, discussed later
in :ref:`fencing`.


.. _primitive-resource:

Resource Properties
###################

These values tell the cluster which resource agent to use for the resource,
where to find that resource agent and what standards it conforms to.

.. list-table:: **Properties of a Primitive Resource**
   :widths: 25 75
   :header-rows: 1

   * - Field
     - Description
   * - id
     - .. index::
          single: id; resource
          single: resource; property, id

       Your name for the resource
   * - class
     - .. index::
          single: class; resource
          single: resource; property, class

       The standard the resource agent conforms to. Allowed values: ``lsb``,
       ``ocf``, ``service``, ``stonith``, and ``systemd``
   * - description
     - .. index::
          single: description; resource
          single: resource; property, description

       Arbitrary text for user's use (ignored by Pacemaker)
   * - type
     - .. index::
          single: type; resource
          single: resource; property, type

       The name of the Resource Agent you wish to use. E.g.  ``IPaddr`` or
       ``Filesystem``
   * - provider
     - .. index::
          single: provider; resource
          single: resource; property, provider

       The OCF spec allows multiple vendors to supply the same resource agent.
       To use the OCF resource agents supplied by the Heartbeat project, you
       would specify ``heartbeat`` here.

The XML definition of a resource can be queried with the **crm_resource** tool.
For example:

.. code-block:: none

   # crm_resource --resource Email --query-xml

might produce:

.. topic:: A system resource definition

   .. code-block:: xml

      <primitive id="Email" class="service" type="exim"/>

.. note::

   One of the main drawbacks to system services (lsb and systemd)
   is that they do not allow parameters

.. topic:: An OCF resource definition

   .. code-block:: xml

      <primitive id="Public-IP" class="ocf" type="IPaddr" provider="heartbeat">
         <instance_attributes id="Public-IP-params">
            <nvpair id="Public-IP-ip" name="ip" value="192.0.2.2"/>
         </instance_attributes>
      </primitive>

.. _resource_options:

Resource Options
################

Resources have two types of options: *meta-attributes* and *instance attributes*.
Meta-attributes apply to any type of resource, while instance attributes
are specific to each resource agent.

Resource Meta-Attributes
________________________

Meta-attributes are used by the cluster to decide how a resource should
behave and can be easily set using the ``--meta`` option of the
**crm_resource** command.

.. list-table:: **Meta-Attributes of a Primitive Resource**
   :class: longtable
   :widths: 20 15 20 45
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description

   * - .. _meta_priority:

       .. index::
          single: priority; resource option
          single: resource; option, priority
          single: resource; meta-attribute, priority
          single: resource meta-attribute; priority

       priority
     - :ref:`score <score>`
     - 0
     - If not all resources can be active, the cluster will stop lower-priority
       resources in order to keep higher-priority ones active.

   * - .. _meta_critical:

       .. index::
          single: critical; resource option
          single: resource; option, critical
          single: resource; meta-attribute, critical
          single: resource meta-attribute; critical

       critical
     - :ref:`boolean <boolean>`
     - true
     - Use this value as the default for ``influence`` in all
       :ref:`colocation constraints <s-resource-colocation>` involving this
       resource, as well as in the implicit colocation constraints created if
       this resource is in a :ref:`group <group-resources>`. For details, see
       :ref:`s-coloc-influence`. *(since 2.1.0)*

   * - .. _meta_target_role:

       .. index::
          single: target-role; resource option
          single: resource; option, target-role
          single: resource; meta-attribute, target-role
          single: resource meta-attribute; target-role

       target-role
     - :ref:`enumeration <enumeration>`
     - Started
     - What state should the cluster attempt to keep this resource in? Allowed
       values:

       * ``Stopped:`` Force the resource to be stopped
       * ``Started:`` Allow the resource to be started (and in the case of
         :ref:`promotable <s-resource-promotable>` clone resources, promoted if
         appropriate)
       * ``Unpromoted:`` Allow the resource to be started, but only in the
         unpromoted role if the resource is
         :ref:`promotable <s-resource-promotable>`
       * ``Promoted:`` Equivalent to ``Started``

   * - .. _meta_is_managed:
       .. _is_managed:

       .. index::
          single: is-managed; resource option
          single: resource; option, is-managed
          single: resource; meta-attribute, is-managed
          single: resource meta-attribute; is-managed

       is-managed
     - :ref:`boolean <boolean>`
     - true
     - If false, the cluster will not start, stop, promote, or demote the
       resource on any node. Recurring actions for the resource are
       unaffected. Maintenance mode overrides this setting.

   * - .. _meta_maintenance:
       .. _rsc_maintenance:

       .. index::
          single: maintenance; resource option
          single: resource; option, maintenance
          single: resource; meta-attribute, maintenance
          single: resource meta-attribute; maintenance

       maintenance
     - :ref:`boolean <boolean>`
     - false
     - If true, the cluster will not start, stop, promote, or demote the
       resource on any node, and will pause any recurring monitors (except those
       specifying ``role`` as ``Stopped``). If true, the
       :ref:`maintenance-mode <maintenance_mode>` cluster option or
       :ref:`maintenance <node_maintenance>` node attribute overrides this.

   * - .. _meta_resource_stickiness:
       .. _resource-stickiness:

       .. index::
          single: resource-stickiness; resource option
          single: resource; option, resource-stickiness
          single: resource; meta-attribute, resource-stickiness
          single: resource meta-attribute; resource-stickiness

       resource-stickiness
     - :ref:`score <score>`
     - 1 for individual clone instances, 0 for all other resources
     - A score that will be added to the current node when a resource is already
       active. This allows running resources to stay where they are, even if
       they would be placed elsewhere if they were being started from a stopped
       state.

   * - .. _meta_requires:
       .. _requires:

       .. index::
          single: requires; resource option
          single: resource; option, requires
          single: resource; meta-attribute, requires
          single: resource meta-attribute; requires

       requires
     - :ref:`enumeration <enumeration>`
     - ``quorum`` for resources with a ``class`` of ``stonith``, otherwise
       ``unfencing`` if unfencing is active in the cluster, otherwise
       ``fencing`` if ``fencing-enabled`` is true, otherwise ``quorum``
     - Conditions under which the resource can be started. Allowed values:

       * ``nothing:`` The cluster can always start this resource.
       * ``quorum:`` The cluster can start this resource only if a majority of
         the configured nodes are active.
       * ``fencing:`` The cluster can start this resource only if a majority of
         the configured nodes are active *and* any failed or unknown nodes have
         been :ref:`fenced <fencing>`.
       * ``unfencing:`` The cluster can only start this resource if a majority
         of the configured nodes are active *and* any failed or unknown nodes
         have been fenced *and* only on nodes that have been
         :ref:`unfenced <unfencing>`.

   * - .. _meta_migration_threshold:

       .. index::
          single: migration-threshold; resource option
          single: resource; option, migration-threshold
          single: resource; meta-attribute, migration-threshold
          single: resource meta-attribute; migration-threshold

       migration-threshold
     - :ref:`score <score>`
     - INFINITY
     - How many failures may occur for this resource on a node, before this node
       is marked ineligible to host this resource. A value of 0 indicates that
       this feature is disabled (the node will never be marked ineligible); by
       contrast, the cluster treats ``INFINITY`` (the default) as a very large
       but finite number. This option has an effect only if the failed operation
       specifies ``on-fail`` as ``restart`` (the default), and additionally for 
       failed ``start`` operations, if the cluster property
       ``start-failure-is-fatal`` is ``false``.

   * - .. _meta_failure_timeout:

       .. index::
          single: failure-timeout; resource option
          single: resource; option, failure-timeout
          single: resource; meta-attribute, failure-timeout
          single: resource meta-attribute; failure-timeout

       failure-timeout
     - :ref:`duration <duration>`
     - 0
     - Ignore previously failed resource actions after this much time has
       passed without new failures (potentially allowing the resource back to
       the node on which it failed, if it previously reached its
       ``migration-threshold`` there). A value of 0 indicates that failures do
       not expire. **WARNING:** If this value is low, and pending cluster
       activity prevents the cluster from responding to a failure within that
       time, then the failure will be ignored completely and will not cause
       recovery of the resource, even if a recurring action continues to report
       failure. It should be at least greater than the longest :ref:`action
       timeout <op_timeout>` for all resources in the cluster. A value in hours
       or days is reasonable.

   * - .. _meta_multiple_active:

       .. index::
          single: multiple-active; resource option
          single: resource; option, multiple-active
          single: resource; meta-attribute, multiple-active
          single: resource meta-attribute; multiple-active

       multiple-active
     - :ref:`enumeration <enumeration>`
     - stop_start
     - What should the cluster do if it ever finds the resource active on more
       than one node? Allowed values:

       * ``block``: mark the resource as unmanaged
       * ``stop_only``: stop all active instances and leave them that way
       * ``stop_start``: stop all active instances and start the resource in one
         location only
       * ``stop_unexpected``: stop all active instances except where the
         resource should be active (this should be used only when extra
         instances are not expected to disrupt existing instances, and the
         resource agent's monitor of an existing instance is capable of
         detecting any problems that could be caused; note that any resources
         ordered after this will still need to be restarted) *(since 2.1.3)*

   * - .. _meta_allow_migrate:

       .. index::
          single: allow-migrate; resource option
          single: resource; option, allow-migrate
          single: resource; meta-attribute, allow-migrate
          single: resource meta-attribute; allow-migrate

       allow-migrate
     - :ref:`boolean <boolean>`
     - true for ``ocf:pacemaker:remote`` resources, false otherwise
     - Whether the cluster should try to "live migrate" this resource when it
       needs to be moved (see :ref:`live-migration`)

   * - .. _meta_allow_unhealthy_nodes:

       .. index::
          single: allow-unhealthy-nodes; resource option
          single: resource; option, allow-unhealthy-nodes
          single: resource; meta-attribute, allow-unhealthy-nodes
          single: resource meta-attribute; allow-unhealthy-nodes

       allow-unhealthy-nodes
     - :ref:`boolean <boolean>`
     - false
     - Whether the resource should be able to run on a node even if the node's
       health score would otherwise prevent it (see :ref:`node-health`) *(since
       2.1.3)*

   * - .. _meta_container_attribute_target:

       .. index::
          single: container-attribute-target; resource option
          single: resource; option, container-attribute-target
          single: resource; meta-attribute, container-attribute-target
          single: resource meta-attribute; container-attribute-target

       container-attribute-target
     - :ref:`enumeration <enumeration>`
     -
     - Specific to bundle resources; see :ref:`s-bundle-attributes`

As an example of setting resource options, if you performed the following
commands on an LSB Email resource:

.. code-block:: none

   # crm_resource --meta --resource Email --set-parameter priority --parameter-value 100
   # crm_resource -m -r Email -p multiple-active -v block

the resulting resource definition might be:

.. topic:: An LSB resource with cluster options

   .. code-block:: xml

      <primitive id="Email" class="lsb" type="exim">
        <meta_attributes id="Email-meta_attributes">
          <nvpair id="Email-meta_attributes-priority" name="priority" value="100"/>
          <nvpair id="Email-meta_attributes-multiple-active" name="multiple-active" value="block"/>
        </meta_attributes>
      </primitive>

In addition to the cluster-defined meta-attributes described above, you may
also configure arbitrary meta-attributes of your own choosing. Most commonly,
this would be done for use in :ref:`rules <rules>`. For example, an IT department
might define a custom meta-attribute to indicate which company department each
resource is intended for. To reduce the chance of name collisions with
cluster-defined meta-attributes added in the future, it is recommended to use
a unique, organization-specific prefix for such attributes.

.. _s-resource-defaults:

Setting Global Defaults for Resource Meta-Attributes
____________________________________________________

To set a default value for a resource option, add it to the
``rsc_defaults`` section with ``crm_attribute``. For example,

.. code-block:: none

   # crm_attribute --type rsc_defaults --name is-managed --update false

would prevent the cluster from starting or stopping any of the
resources in the configuration (unless of course the individual
resources were specifically enabled by having their ``is-managed`` set to
``true``).

Resource Instance Attributes
____________________________

The resource agents of some resource standards (lsb and systemd *not* among
them) can be given parameters which determine how they behave and which
instance of a service they control.

If your resource agent supports parameters, you can add them with the
``crm_resource`` command. For example,

.. code-block:: none

   # crm_resource --resource Public-IP --set-parameter ip --parameter-value 192.0.2.2

would create an entry in the resource like this:

.. topic:: An example OCF resource with instance attributes

   .. code-block:: xml

      <primitive id="Public-IP" class="ocf" type="IPaddr" provider="heartbeat">
         <instance_attributes id="params-public-ip">
            <nvpair id="public-ip-addr" name="ip" value="192.0.2.2"/>
         </instance_attributes>
      </primitive>

For an OCF resource, the result would be an environment variable
called ``OCF_RESKEY_ip`` with a value of ``192.0.2.2``.

The list of instance attributes supported by an OCF resource agent can be
found by calling the resource agent with the ``meta-data`` command.
The output contains an XML description of all the supported
attributes, their purpose and default values.

.. topic:: Displaying the metadata for the Dummy resource agent template

   .. code-block:: none

      # export OCF_ROOT=/usr/lib/ocf
      # $OCF_ROOT/resource.d/pacemaker/Dummy meta-data

   .. code-block:: xml

      <?xml version="1.0"?>
      <!DOCTYPE resource-agent SYSTEM "ra-api-1.dtd">
      <resource-agent name="Dummy" version="2.0">
      <version>1.1</version>

      <longdesc lang="en">
      This is a dummy OCF resource agent. It does absolutely nothing except keep track
      of whether it is running or not, and can be configured so that actions fail or
      take a long time. Its purpose is primarily for testing, and to serve as a
      template for resource agent writers.
      </longdesc>
      <shortdesc lang="en">Example stateless resource agent</shortdesc>

      <parameters>
      <parameter name="state" unique-group="state">
      <longdesc lang="en">
      Location to store the resource state in.
      </longdesc>
      <shortdesc lang="en">State file</shortdesc>
      <content type="string" default="/var/run/Dummy-RESOURCE_ID.state" />
      </parameter>

      <parameter name="passwd" reloadable="1">
      <longdesc lang="en">
      Fake password field
      </longdesc>
      <shortdesc lang="en">Password</shortdesc>
      <content type="string" default="" />
      </parameter>

      <parameter name="fake" reloadable="1">
      <longdesc lang="en">
      Fake attribute that can be changed to cause a reload
      </longdesc>
      <shortdesc lang="en">Fake attribute that can be changed to cause a reload</shortdesc>
      <content type="string" default="dummy" />
      </parameter>

      <parameter name="op_sleep" reloadable="1">
      <longdesc lang="en">
      Number of seconds to sleep during operations.  This can be used to test how
      the cluster reacts to operation timeouts.
      </longdesc>
      <shortdesc lang="en">Operation sleep duration in seconds.</shortdesc>
      <content type="string" default="0" />
      </parameter>

      <parameter name="fail_start_on" reloadable="1">
      <longdesc lang="en">
      Start, migrate_from, and reload-agent actions will return failure if running on
      the host specified here, but the resource will run successfully anyway (future
      monitor calls will find it running). This can be used to test on-fail=ignore.
      </longdesc>
      <shortdesc lang="en">Report bogus start failure on specified host</shortdesc>
      <content type="string" default="" />
      </parameter>
      <parameter name="envfile" reloadable="1">
      <longdesc lang="en">
      If this is set, the environment will be dumped to this file for every call.
      </longdesc>
      <shortdesc lang="en">Environment dump file</shortdesc>
      <content type="string" default="" />
      </parameter>

      </parameters>

      <actions>
      <action name="start"        timeout="20s" />
      <action name="stop"         timeout="20s" />
      <action name="monitor"      timeout="20s" interval="10s" depth="0"/>
      <action name="reload"       timeout="20s" />
      <action name="reload-agent" timeout="20s" />
      <action name="migrate_to"   timeout="20s" />
      <action name="migrate_from" timeout="20s" />
      <action name="validate-all" timeout="20s" />
      <action name="meta-data"    timeout="5s" />
      </actions>
      </resource-agent>


Pacemaker Remote Resources
##########################

:ref:`Pacemaker Remote <pacemaker_remote>` nodes are defined by resources.

.. _remote_nodes:

.. index::
   single: node; remote
   single: Pacemaker Remote; remote node
   single: remote node

Remote nodes
____________

A remote node is defined by a connection resource using the special,
built-in **ocf:pacemaker:remote** resource agent.

.. list-table:: **ocf:pacemaker:remote Instance Attributes**
   :class: longtable
   :widths: 25 10 15 50
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description

   * - .. _remote_server:

       .. index::
          pair: remote node; server

       server
     - :ref:`text <text>`
     - resource ID
     - Hostname or IP address used to connect to the remote node. The remote
       executor on the remote node must be configured to accept connections on
       this address.

   * - .. _remote_port:

       .. index::
          pair: remote node; port

       port
     - :ref:`port <port>`
     - 3121
     - TCP port on the remote node used for its Pacemaker Remote connection.
       The remote executor on the remote node must be configured to listen on
       this port.

   * - .. _remote_reconnect_interval:

       .. index::
          pair: remote node; reconnect_interval

       reconnect_interval
     - :ref:`duration <duration>`
     - 0
     - If positive, the cluster will attempt to reconnect to a remote node
       at this interval after an active connection has been lost. Otherwise,
       the cluster will attempt to reconnect immediately (after any fencing, if
       needed).

.. _guest_nodes:

.. index::
   single: node; guest
   single: Pacemaker Remote; guest node
   single: guest node

Guest Nodes
___________

When configuring a virtual machine as a guest node, the virtual machine is
created using one of the usual resource agents for that purpose (for example,
**ocf:heartbeat:VirtualDomain** or **ocf:heartbeat:Xen**), with additional
meta-attributes.

No restrictions are enforced on what agents may be used to create a guest node,
but obviously the agent must create a distinct environment capable of running
the remote executor and cluster resources. An additional requirement is that
fencing the node hosting the guest node resource must be sufficient for
ensuring the guest node is stopped. This means that not all hypervisors
supported by **VirtualDomain** may be used to create guest nodes; if the guest
can survive the hypervisor being fenced, it is unsuitable for use as a guest
node.

.. list-table:: **Guest Node Meta-Attributes**
   :class: longtable
   :widths: 25 10 20 45
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description

   * - .. _meta_remote_node:

       .. index::
          single: remote-node; resource option
          single: resource; option, remote-node
          single: resource; meta-attribute, remote-node
          single: resource meta-attribute; remote-node

       remote-node
     - :ref:`text <text>`
     -
     - If specified, this resource defines a guest node using this node name.
       The guest must be configured to run the remote executor when it is
       started. This value *must not* be the same as any resource or node ID.

   * - .. _meta_remote_addr:

       .. index::
          single: remote-addr; resource option
          single: resource; option, remote-addr
          single: resource; meta-attribute, remote-addr
          single: resource meta-attribute; remote-addr

       remote-addr
     - :ref:`text <text>`
     - value of ``remote-node``
     - If ``remote-node`` is specified, the hostname or IP address used to
       connect to the guest. The remote executor on the guest must be
       configured to accept connections on this address.

   * - .. _meta_remote_port:

       .. index::
          single: remote-port; resource option
          single: resource; option, remote-port
          single: resource; meta-attribute, remote-port
          single: resource meta-attribute; remote-port

       remote-port
     - :ref:`port <port>`
     - 3121
     - If ``remote-node`` is specified, the port on the guest used for its
       Pacemaker Remote connection. The remote executor on the guest must be
       configured to listen on this port.

   * - .. _meta_remote_connect_timeout:

       .. index::
          single: remote-connect-timeout; resource option
          single: resource; option, remote-connect-timeout
          single: resource; meta-attribute, remote-connect-timeout
          single: resource meta-attribute; remote-connect-timeout

       remote-connect-timeout
     - :ref:`timeout <timeout>`
     - 60s
     - If ``remote-node`` is specified, how long before a pending guest
       connection will time out.

   * - .. _meta_remote_allow_migrate:

       .. index::
          single: remote-allow-migrate; resource option
          single: resource; option, remote-allow-migrate
          single: resource; meta-attribute, remote-allow-migrate
          single: resource meta-attribute; remote-allow-migrate

       remote-allow-migrate
     - :ref:`boolean <boolean>`
     - true
     - If ``remote-node`` is specified, this acts as the ``allow-migrate``
       meta-attribute for its implicitly created remote connection resource
       (``ocf:pacemaker:remote``).

Removing Pacemaker Remote Nodes
_______________________________

If the resource creating a remote node connection or guest node is removed from
the configuration, status output may continue to show the affected node (as
offline).

If you want to get rid of that output, run the following command, replacing
``$NODE_NAME`` appropriately:

.. code-block:: none

    # crm_node --force --remove $NODE_NAME

.. WARNING::

    Be absolutely sure that there are no references to the node's resource in the
    configuration before running the above command.
