.. _resource:

Cluster Resources
-----------------

.. _s-resource-primitive:

What is a Cluster Resource?
###########################

.. index::
   single: resource

A *resource* is a service managed by Pacemaker. The simplest type of resource,
a *primitive*, is described in this chapter. More complex forms, such as groups
and clones, are described in later chapters.

Every primitive has a *resource agent* that provides Pacemaker a standardized
interface for managing the service. This allows Pacemaker to be agnostic about
the services it manages. Pacemaker doesn't need to understand how the service
works because it relies on the resource agent to do the right thing when asked.

Every resource has a *class* specifying the standard that its resource agent
follows, and a *type* identifying the specific service being managed.


.. _s-resource-supported:

.. index::
   single: resource; class
 
Resource Classes
################

Pacemaker supports several classes, or standards, of resource agents:

* OCF
* LSB
* Systemd
* Service
* Fencing
* Nagios *(deprecated since 2.1.6)*
* Upstart *(deprecated since 2.1.0)*


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
flexible than other classes. The number and purpose of parameters is left to
the agent, which advertises them via the ``meta-data`` action.

Unlike other classes, OCF agents have a *provider* as well as a class and type.

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

Pacemaker can manage systemd services. Simply create a resource with
``systemd`` as the resource class and the unit file name as the resource type.
Do *not* run ``systemctl enable`` on the unit.

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

Since there are various types of system services (``systemd``,
``upstart``, and ``lsb``), Pacemaker supports a special ``service`` alias which
intelligently figures out which one applies to a given cluster node.

This is particularly useful when the cluster contains a mix of
``systemd``, ``upstart``, and ``lsb``.

In order, Pacemaker will try to find the named service as:

* an LSB init script
* a Systemd unit file
* an Upstart job


.. index::
   single: Resource; STONITH
   single: STONITH; resources

STONITH
_______

The ``stonith`` class is used for managing fencing devices, discussed later in
:ref:`fencing`.


.. index::
   single: Resource; Nagios Plugins
   single: Nagios Plugins; resources

Nagios Plugins
______________

Nagios Plugins are a way to monitor services. Pacemaker can use these as
resources, to react to a change in the service's status.

To use plugins as resources, Pacemaker must have been built with support, and
OCF-style meta-data for the plugins must be installed on nodes that can run
them. Meta-data for several common plugins is provided by the
`nagios-agents-metadata <https://github.com/ClusterLabs/nagios-agents-metadata>`_
project.

The supported parameters for such a resource are same as the long options of
the plugin.

Start and monitor actions for plugin resources are implemented as invoking the
plugin. A plugin result of "OK" (0) is treated as success, a result of "WARN"
(1) is treated as a successful but degraded service, and any other result is
considered a failure.

A plugin resource is not going to change its status after recovery by
restarting the plugin, so using them alone does not make sense with ``on-fail``
set (or left to default) to ``restart``. Another value could make sense, for
example, if you want to fence or standby nodes that cannot reach some external
service.

A more common use case for plugin resources is to configure them with a
``container`` meta-attribute set to the name of another resource that actually
makes the service available, such as a virtual machine or container.

With ``container`` set, the plugin resource will automatically be colocated
with the containing resource and ordered after it, and the containing resource
will be considered failed if the plugin resource fails. This allows monitoring
of a service inside a virtual machine or container, with recovery of the
virtual machine or container if the service fails.

.. warning::

   Nagios support is deprecated in Pacemaker. Support will be dropped entirely
   at the next major release of Pacemaker.

   For monitoring a service inside a virtual machine or container, the
   recommended alternative is to configure the virtual machine as a guest node
   or the container as a :ref:`bundle <s-resource-bundle>`. For other use
   cases, or when the virtual machine or container image cannot be modified,
   the recommended alternative is to write a custom OCF agent for the service
   (which may even call the Nagios plugin as part of its status action).


.. index::
   single: Resource; Upstart
   single: Upstart; resources

Upstart
_______

Some Linux distributions previously used `Upstart
<https://upstart.ubuntu.com/>`_ for system initialization and service
management. Pacemaker is able to manage services using Upstart if the local
system supports them and support was enabled when your Pacemaker software was
built.

The *jobs* that specify how services are managed are usually provided by the
operating system distribution.

.. important::

   Make sure the host is *not* configured to start any Upstart services at boot
   that will be controlled by the cluster.

.. warning::

   Upstart support is deprecated in Pacemaker. Upstart is no longer actively
   maintained, and test platforms for it are no longer readily usable. Support
   will be dropped entirely at the next major release of Pacemaker.


.. _primitive-resource:

Resource Properties
###################

These values tell the cluster which resource agent to use for the resource,
where to find that resource agent and what standards it conforms to.

.. table:: **Properties of a Primitive Resource**
   :widths: 1 4

   +-------------+------------------------------------------------------------------+
   | Field       | Description                                                      |
   +=============+==================================================================+
   | id          | .. index::                                                       |
   |             |    single: id; resource                                          |
   |             |    single: resource; property, id                                |
   |             |                                                                  |
   |             | Your name for the resource                                       |
   +-------------+------------------------------------------------------------------+
   | class       | .. index::                                                       |
   |             |    single: class; resource                                       |
   |             |    single: resource; property, class                             |
   |             |                                                                  |
   |             | The standard the resource agent conforms to. Allowed values:     |
   |             | ``lsb``, ``ocf``, ``service``, ``stonith``, ``systemd``,         |
   |             | ``nagios`` *(deprecated since 2.1.6)*, and ``upstart``           |
   |             | *(deprecated since 2.1.0)*                                       |
   +-------------+------------------------------------------------------------------+
   | description | .. index::                                                       |
   |             |    single: description; resource                                 |
   |             |    single: resource; property, description                       |
   |             |                                                                  |
   |             | A description of the Resource Agent, intended for local use.     |
   |             | E.g. ``IP address for website``                                  |
   +-------------+------------------------------------------------------------------+
   | type        | .. index::                                                       |
   |             |    single: type; resource                                        |
   |             |    single: resource; property, type                              |
   |             |                                                                  |
   |             | The name of the Resource Agent you wish to use. E.g.             |
   |             | ``IPaddr`` or ``Filesystem``                                     |
   +-------------+------------------------------------------------------------------+
   | provider    | .. index::                                                       |
   |             |    single: provider; resource                                    |
   |             |    single: resource; property, provider                          |
   |             |                                                                  |
   |             | The OCF spec allows multiple vendors to supply the same resource |
   |             | agent. To use the OCF resource agents supplied by the Heartbeat  |
   |             | project, you would specify ``heartbeat`` here.                   |
   +-------------+------------------------------------------------------------------+

The XML definition of a resource can be queried with the **crm_resource** tool.
For example:

.. code-block:: none

   # crm_resource --resource Email --query-xml

might produce:

.. topic:: A system resource definition

   .. code-block:: xml

      <primitive id="Email" class="service" type="exim"/>

.. note::

   One of the main drawbacks to system services (LSB, systemd or
   Upstart) resources is that they do not allow any parameters!

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

.. list-table:: **Meta-attributes of a Primitive Resource**
   :class: longtable
   :widths: 2 2 3 5
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description

   * - .. _meta_priority:
       
       .. index::
          single: priority; resource option
          single: resource; option, priority

       priority
     - :ref:`score <score>`
     - 0
     - If not all resources can be active, the cluster will stop lower-priority
       resources in order to keep higher-priority ones active.

   * - .. _meta_critical:
       
       .. index::
          single: critical; resource option
          single: resource; option, critical

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

       is-managed
     - :ref:`boolean <boolean>`
     - true
     - If false, the cluster will not start or stop the resource on any node.
       Recurring actions for the resource are unaffected. Maintenance mode
       overrides this setting.

   * - .. _meta_maintenance:
       .. _rsc_maintenance:
       
       .. index::
          single: maintenance; resource option
          single: resource; option, maintenance

       maintenance
     - :ref:`boolean <boolean>`
     - false
     - If true, the cluster will not start or stop the resource on any node, and
       will pause any recurring monitors (except those specifying ``role`` as
       ``Stopped``). If true, the :ref:`maintenance-mode <maintenance_mode>`
       cluster option or :ref:`maintenance <node_maintenance>` node attribute
       override this.

   * - .. _meta_resource_stickiness:
       .. _resource-stickiness:
       
       .. index::
          single: resource-stickiness; resource option
          single: resource; option, resource-stickiness

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

       requires
     - :ref:`enumeration <enumeration>`
     - ``quorum`` for resources with a ``class`` of ``stonith``, otherwise
       ``unfencing`` if unfencing is active in the cluster, otherwise
       ``fencing`` if ``stonith-enabled`` is true, otherwise ``quorum``
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

       failure-timeout
     - :ref:`duration <duration>`
     - 0
     - How many seconds to wait before acting as if the failure had not
       occurred, and potentially allowing the resource back to the node on which
       it failed. A value of 0 indicates that this feature is disabled.

   * - .. _meta_multiple_active:
       
       .. index::
          single: multiple-active; resource option
          single: resource; option, multiple-active

       multiple-active
     - :ref:`enumeration <enumeration>`
     - stop_start
     - What should the cluster do if it ever finds the resource active on more
       than one node? Allowed values:

       * ``block``: mark the resource as unmanaged
       * ``stop_only``: stop all active instances and leave them that way
       * `stop_start``: stop all active instances and start the resource in one
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

       allow-migrate
     - :ref:`boolean <boolean>`
     - true for ``ocf:pacemaker:remote`` resources, false otherwise
     - Whether the cluster should try to "live migrate" this resource when it
       needs to be moved (see :ref:`live-migration`)

   * - .. _meta_allow_unhealthy_nodes:
       
       .. index::
          single: allow-unhealthy-nodes; resource option
          single: resource; option, allow-unhealthy-nodes

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

       container-attribute-target
     - :ref:`enumeration <enumeration>`
     -
     - Specific to bundle resources; see :ref:`s-bundle-attributes`

   * - .. _meta_remote_node:
       
       .. index::
          single: remote-node; resource option
          single: resource; option, remote-node

       remote-node
     - :ref:`text <text>`
     -
     - The name of the Pacemaker Remote guest node this resource is associated
       with, if any. If specified, this both enables the resource as a guest
       node and defines the unique name used to identify the guest node. The
       guest must be configured to run the Pacemaker Remote daemon when it is
       started. **WARNING:** This value cannot overlap with any resource or node
       IDs.

   * - .. _meta_remote_addr:
       
       .. index::
          single: remote-addr; resource option
          single: resource; option, remote-addr

       remote-addr
     - :ref:`text <text>`
     - value of ``remote-node``
     - If ``remote-node`` is specified, the IP address or hostname used to
       connect to the guest via Pacemaker Remote. The Pacemaker Remote daemon on
       the guest must be configured to accept connections on this address.

   * - .. _meta_remote_port:
       
       .. index::
          single: remote-port; resource option
          single: resource; option, remote-port

       remote-port
     - :ref:`port <port>`
     - 3121
     - If ``remote-node`` is specified, the port on the guest used for its
       Pacemaker Remote connection. The Pacemaker Remote daemon on the guest
       must be configured to listen on this port.

   * - .. _meta_remote_connect_timeout:
       
       .. index::
          single: remote-connect-timeout; resource option
          single: resource; option, remote-connect-timeout

       remote-connect-timeout
     - :ref:`timeout <timeout>`
     - 60s
     - If ``remote-node`` is specified, how long before a pending guest
       connection will time out.


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

The resource agents of some resource classes (lsb, systemd and upstart *not* among them)
can be given parameters which determine how they behave and which instance
of a service they control.

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
