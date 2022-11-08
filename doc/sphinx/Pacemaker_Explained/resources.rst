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
* Upstart (deprecated)
* Service
* Fencing
* Nagios


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

Nagios Plugins [#]_ are a way to monitor services. Pacemaker can use these as
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

Configuring a virtual machine as a guest node, or a container as a
:ref:`bundle <s-resource-bundle>`, is the preferred way of monitoring a service
inside, but plugin resources can be useful when it is not practical to modify
the virtual machine or container image for this purpose.


.. _primitive-resource:

Resource Properties
###################

These values tell the cluster which resource agent to use for the resource,
where to find that resource agent and what standards it conforms to.

.. table:: **Properties of a Primitive Resource**
   :widths: 1 4

   +----------+------------------------------------------------------------------+
   | Field    | Description                                                      |
   +==========+==================================================================+
   | id       | .. index::                                                       |
   |          |    single: id; resource                                          |
   |          |    single: resource; property, id                                |
   |          |                                                                  |
   |          | Your name for the resource                                       |
   +----------+------------------------------------------------------------------+
   | class    | .. index::                                                       |
   |          |    single: class; resource                                       |
   |          |    single: resource; property, class                             |
   |          |                                                                  |
   |          | The standard the resource agent conforms to. Allowed values:     |
   |          | ``lsb``, ``nagios``, ``ocf``, ``service``, ``stonith``,          |
   |          | ``systemd``, ``upstart``                                         |
   +----------+------------------------------------------------------------------+
   | type     | .. index::                                                       |
   |          |    single: type; resource                                        |
   |          |    single: resource; property, type                              |
   |          |                                                                  |
   |          | The name of the Resource Agent you wish to use. E.g.             |
   |          | ``IPaddr`` or ``Filesystem``                                     |
   +----------+------------------------------------------------------------------+
   | provider | .. index::                                                       |
   |          |    single: provider; resource                                    |
   |          |    single: resource; property, provider                          |
   |          |                                                                  |
   |          | The OCF spec allows multiple vendors to supply the same resource |
   |          | agent. To use the OCF resource agents supplied by the Heartbeat  |
   |          | project, you would specify ``heartbeat`` here.                   |
   +----------+------------------------------------------------------------------+

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

.. table:: **Meta-attributes of a Primitive Resource**
   :class: longtable
   :widths: 2 2 3

   +----------------------------+----------------------------------+------------------------------------------------------+
   | Field                      | Default                          | Description                                          |
   +============================+==================================+======================================================+
   | priority                   | 0                                | .. index::                                           |
   |                            |                                  |    single: priority; resource option                 |
   |                            |                                  |    single: resource; option, priority                |
   |                            |                                  |                                                      |
   |                            |                                  | If not all resources can be active, the cluster      |
   |                            |                                  | will stop lower priority resources in order to       |
   |                            |                                  | keep higher priority ones active.                    |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | critical                   | true                             | .. index::                                           |
   |                            |                                  |    single: critical; resource option                 |
   |                            |                                  |    single: resource; option, critical                |
   |                            |                                  |                                                      |
   |                            |                                  | Use this value as the default for ``influence`` in   |
   |                            |                                  | all :ref:`colocation constraints                     |
   |                            |                                  | <s-resource-colocation>` involving this resource,    |
   |                            |                                  | as well as the implicit colocation constraints       |
   |                            |                                  | created if this resource is in a :ref:`group         |
   |                            |                                  | <group-resources>`. For details, see                 |
   |                            |                                  | :ref:`s-coloc-influence`. *(since 2.1.0)*            |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | target-role                | Started                          | .. index::                                           |
   |                            |                                  |    single: target-role; resource option              |
   |                            |                                  |    single: resource; option, target-role             |
   |                            |                                  |                                                      |
   |                            |                                  | What state should the cluster attempt to keep this   |
   |                            |                                  | resource in? Allowed values:                         |
   |                            |                                  |                                                      |
   |                            |                                  | * ``Stopped:`` Force the resource to be stopped      |
   |                            |                                  | * ``Started:`` Allow the resource to be started      |
   |                            |                                  |   (and in the case of :ref:`promotable clone         |
   |                            |                                  |   resources <s-resource-promotable>`, promoted       |
   |                            |                                  |   if appropriate)                                    |
   |                            |                                  | * ``Unpromoted:`` Allow the resource to be started,  |
   |                            |                                  |   but only in the unpromoted role if the resource is |
   |                            |                                  |   :ref:`promotable <s-resource-promotable>`          |
   |                            |                                  | * ``Promoted:`` Equivalent to ``Started``            |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | is-managed                 | TRUE                             | .. index::                                           |
   |                            |                                  |    single: is-managed; resource option               |
   |                            |                                  |    single: resource; option, is-managed              |
   |                            |                                  |                                                      |
   |                            |                                  | Is the cluster allowed to start and stop             |
   |                            |                                  | the resource?  Allowed values: ``true``, ``false``   |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | maintenance                | FALSE                            | .. index::                                           |
   |                            |                                  |    single: maintenance; resource option              |
   |                            |                                  |    single: resource; option, maintenance             |
   |                            |                                  |                                                      |
   |                            |                                  | Similar to the ``maintenance-mode``                  |
   |                            |                                  | :ref:`cluster option <cluster_options>`, but for     |
   |                            |                                  | a single resource. If true, the resource will not    |
   |                            |                                  | be started, stopped, or monitored on any node. This  |
   |                            |                                  | differs from ``is-managed`` in that monitors will    |
   |                            |                                  | not be run. Allowed values: ``true``, ``false``      |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | resource-stickiness        | 1 for individual clone           | .. _resource-stickiness:                             |
   |                            | instances, 0 for all             |                                                      |
   |                            | other resources                  | .. index::                                           |
   |                            |                                  |    single: resource-stickiness; resource option      |
   |                            |                                  |    single: resource; option, resource-stickiness     |
   |                            |                                  |                                                      |
   |                            |                                  | A score that will be added to the current node when  |
   |                            |                                  | a resource is already active. This allows running    |
   |                            |                                  | resources to stay where they are, even if they       |
   |                            |                                  | would be placed elsewhere if they were being         |
   |                            |                                  | started from a stopped state.                        |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | requires                   | ``quorum`` for resources         | .. _requires:                                        |
   |                            | with a ``class`` of ``stonith``, |                                                      |
   |                            | otherwise ``unfencing`` if       | .. index::                                           |
   |                            | unfencing is active in the       |    single: requires; resource option                 |
   |                            | cluster, otherwise ``fencing``   |    single: resource; option, requires                |
   |                            | if ``stonith-enabled`` is true,  |                                                      |
   |                            | otherwise ``quorum``             | Conditions under which the resource can be           |
   |                            |                                  | started. Allowed values:                             |
   |                            |                                  |                                                      |
   |                            |                                  | * ``nothing:`` can always be started                 |
   |                            |                                  | * ``quorum:`` The cluster can only start this        |
   |                            |                                  |   resource if a majority of the configured nodes     |
   |                            |                                  |   are active                                         |
   |                            |                                  | * ``fencing:`` The cluster can only start this       |
   |                            |                                  |   resource if a majority of the configured nodes     |
   |                            |                                  |   are active *and* any failed or unknown nodes       |
   |                            |                                  |   have been :ref:`fenced <fencing>`                  |
   |                            |                                  | * ``unfencing:`` The cluster can only start this     |
   |                            |                                  |   resource if a majority of the configured nodes     |
   |                            |                                  |   are active *and* any failed or unknown nodes have  |
   |                            |                                  |   been fenced *and* only on nodes that have been     |
   |                            |                                  |   :ref:`unfenced <unfencing>`                        |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | migration-threshold        | INFINITY                         | .. index::                                           |
   |                            |                                  |    single: migration-threshold; resource option      |
   |                            |                                  |    single: resource; option, migration-threshold     |
   |                            |                                  |                                                      |
   |                            |                                  | How many failures may occur for this resource on     |
   |                            |                                  | a node, before this node is marked ineligible to     |
   |                            |                                  | host this resource. A value of 0 indicates that this |
   |                            |                                  | feature is disabled (the node will never be marked   |
   |                            |                                  | ineligible); by constrast, the cluster treats        |
   |                            |                                  | INFINITY (the default) as a very large but finite    |
   |                            |                                  | number. This option has an effect only if the        |
   |                            |                                  | failed operation specifies ``on-fail`` as            |
   |                            |                                  | ``restart`` (the default), and additionally for      |
   |                            |                                  | failed ``start`` operations, if the cluster          |
   |                            |                                  | property ``start-failure-is-fatal`` is ``false``.    |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | failure-timeout            | 0                                | .. index::                                           |
   |                            |                                  |    single: failure-timeout; resource option          |
   |                            |                                  |    single: resource; option, failure-timeout         |
   |                            |                                  |                                                      |
   |                            |                                  | How many seconds to wait before acting as if the     |
   |                            |                                  | failure had not occurred, and potentially allowing   |
   |                            |                                  | the resource back to the node on which it failed.    |
   |                            |                                  | A value of 0 indicates that this feature is          |
   |                            |                                  | disabled.                                            |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | multiple-active            | stop_start                       | .. index::                                           |
   |                            |                                  |    single: multiple-active; resource option          |
   |                            |                                  |    single: resource; option, multiple-active         |
   |                            |                                  |                                                      |
   |                            |                                  | What should the cluster do if it ever finds the      |
   |                            |                                  | resource active on more than one node? Allowed       |
   |                            |                                  | values:                                              |
   |                            |                                  |                                                      |
   |                            |                                  | * ``block``: mark the resource as unmanaged          |
   |                            |                                  | * ``stop_only``: stop all active instances and       |
   |                            |                                  |   leave them that way                                |
   |                            |                                  | * ``stop_start``: stop all active instances and      |
   |                            |                                  |   start the resource in one location only            |
   |                            |                                  | * ``stop_unexpected``: stop all active instances     |
   |                            |                                  |   except where the resource should be active (this   |
   |                            |                                  |   should be used only when extra instances are not   |
   |                            |                                  |   expected to disrupt existing instances, and the    |
   |                            |                                  |   resource agent's monitor of an existing instance   |
   |                            |                                  |   is capable of detecting any problems that could be |
   |                            |                                  |   caused; note that any resources ordered after this |
   |                            |                                  |   will still need to be restarted)                   |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | allow-migrate              | TRUE for ocf:pacemaker:remote    | Whether the cluster should try to "live migrate"     |
   |                            | resources, FALSE otherwise       | this resource when it needs to be moved (see         |
   |                            |                                  | :ref:`live-migration`)                               |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | allow-unhealthy-nodes      | FALSE                            | Whether the resource should be able to run on a node |
   |                            |                                  | even if the node's health score would otherwise      |
   |                            |                                  | prevent it (see :ref:`node-health`) *(since 2.1.3)*  |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | container-attribute-target |                                  | Specific to bundle resources; see                    |
   |                            |                                  | :ref:`s-bundle-attributes`                           |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | remote-node                |                                  | The name of the Pacemaker Remote guest node this     |
   |                            |                                  | resource is associated with, if any. If              |
   |                            |                                  | specified, this both enables the resource as a       |
   |                            |                                  | guest node and defines the unique name used to       |
   |                            |                                  | identify the guest node. The guest must be           |
   |                            |                                  | configured to run the Pacemaker Remote daemon        |
   |                            |                                  | when it is started. **WARNING:** This value          |
   |                            |                                  | cannot overlap with any resource or node IDs.        |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | remote-port                | 3121                             | If ``remote-node`` is specified, the port on the     |
   |                            |                                  | guest used for its Pacemaker Remote connection.      |
   |                            |                                  | The Pacemaker Remote daemon on the guest must        |
   |                            |                                  | be configured to listen on this port.                |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | remote-addr                | value of ``remote-node``         | If ``remote-node`` is specified, the IP              |
   |                            |                                  | address or hostname used to connect to the           |
   |                            |                                  | guest via Pacemaker Remote. The Pacemaker Remote     |
   |                            |                                  | daemon on the guest must be configured to accept     |
   |                            |                                  | connections on this address.                         |
   +----------------------------+----------------------------------+------------------------------------------------------+
   | remote-connect-timeout     | 60s                              | If ``remote-node`` is specified, how long before     |
   |                            |                                  | a pending guest connection will time out.            |
   +----------------------------+----------------------------------+------------------------------------------------------+

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

.. index::
   single: resource; action
   single: resource; operation

.. _operation:

Resource Operations
###################

*Operations* are actions the cluster can perform on a resource by calling the
resource agent. Resource agents must support certain common operations such as
start, stop, and monitor, and may implement any others.

Operations may be explicitly configured for two purposes: to override defaults
for options (such as timeout) that the cluster will use whenever it initiates
the operation, and to run an operation on a recurring basis (for example, to
monitor the resource for failure).

.. topic:: An OCF resource with a non-default start timeout

   .. code-block:: xml

      <primitive id="Public-IP" class="ocf" type="IPaddr" provider="heartbeat">
        <operations>
           <op id="Public-IP-start" name="start" timeout="60s"/>
        </operations>
        <instance_attributes id="params-public-ip">
           <nvpair id="public-ip-addr" name="ip" value="192.0.2.2"/>
        </instance_attributes>
      </primitive>

Pacemaker identifies operations by a combination of name and interval, so this
combination must be unique for each resource. That is, you should not configure
two operations for the same resource with the same name and interval.

.. _operation_properties:

Operation Properties
____________________

Operation properties may be specified directly in the ``op`` element as
XML attributes, or in a separate ``meta_attributes`` block as ``nvpair`` elements.
XML attributes take precedence over ``nvpair`` elements if both are specified.

.. table:: **Properties of an Operation**
   :class: longtable
   :widths: 1 2 3

   +----------------+-----------------------------------+-----------------------------------------------------+
   | Field          | Default                           | Description                                         |
   +================+===================================+=====================================================+
   | id             |                                   | .. index::                                          |
   |                |                                   |    single: id; action property                      |
   |                |                                   |    single: action; property, id                     |
   |                |                                   |                                                     |
   |                |                                   | A unique name for the operation.                    |
   +----------------+-----------------------------------+-----------------------------------------------------+
   | name           |                                   | .. index::                                          |
   |                |                                   |    single: name; action property                    |
   |                |                                   |    single: action; property, name                   |
   |                |                                   |                                                     |
   |                |                                   | The action to perform. This can be any action       |
   |                |                                   | supported by the agent; common values include       |
   |                |                                   | ``monitor``, ``start``, and ``stop``.               |
   +----------------+-----------------------------------+-----------------------------------------------------+
   | interval       | 0                                 | .. index::                                          |
   |                |                                   |    single: interval; action property                |
   |                |                                   |    single: action; property, interval               |
   |                |                                   |                                                     |
   |                |                                   | How frequently (in seconds) to perform the          |
   |                |                                   | operation. A value of 0 means "when needed".        |
   |                |                                   | A positive value defines a *recurring action*,      |
   |                |                                   | which is typically used with                        |
   |                |                                   | :ref:`monitor <s-resource-monitoring>`.             |
   +----------------+-----------------------------------+-----------------------------------------------------+
   | timeout        |                                   | .. index::                                          |
   |                |                                   |    single: timeout; action property                 |
   |                |                                   |    single: action; property, timeout                |
   |                |                                   |                                                     |
   |                |                                   | How long to wait before declaring the action        |
   |                |                                   | has failed                                          |
   +----------------+-----------------------------------+-----------------------------------------------------+
   | on-fail        | Varies by action:                 | .. index::                                          |
   |                |                                   |    single: on-fail; action property                 |
   |                | * ``stop``: ``fence`` if          |    single: action; property, on-fail                |
   |                |   ``stonith-enabled`` is true     |                                                     |
   |                |   or ``block`` otherwise          | The action to take if this action ever fails.       |
   |                | * ``demote``: ``on-fail`` of the  | Allowed values:                                     |
   |                |   ``monitor`` action with         |                                                     |
   |                |   ``role`` set to ``Promoted``,   | * ``ignore:`` Pretend the resource did not fail.    |
   |                |   if present, enabled, and        | * ``block:`` Don't perform any further operations   |
   |                |   configured to a value other     |   on the resource.                                  |
   |                |   than ``demote``, or ``restart`` | * ``stop:`` Stop the resource and do not start      |
   |                |   otherwise                       |   it elsewhere.                                     |
   |                | * all other actions: ``restart``  | * ``demote:`` Demote the resource, without a        |
   |                |                                   |   full restart. This is valid only for ``promote``  |
   |                |                                   |   actions, and for ``monitor`` actions with both    |
   |                |                                   |   a nonzero ``interval`` and ``role`` set to        |
   |                |                                   |   ``Promoted``; for any other action, a             |
   |                |                                   |   configuration error will be logged, and the       |
   |                |                                   |   default behavior will be used. *(since 2.0.5)*    |
   |                |                                   | * ``restart:`` Stop the resource and start it       |
   |                |                                   |   again (possibly on a different node).             |
   |                |                                   | * ``fence:`` STONITH the node on which the          |
   |                |                                   |   resource failed.                                  |
   |                |                                   | * ``standby:`` Move *all* resources away from the   |
   |                |                                   |   node on which the resource failed.                |
   +----------------+-----------------------------------+-----------------------------------------------------+
   | enabled        | TRUE                              | .. index::                                          |
   |                |                                   |    single: enabled; action property                 |
   |                |                                   |    single: action; property, enabled                |
   |                |                                   |                                                     |
   |                |                                   | If ``false``, ignore this operation definition.     |
   |                |                                   | This is typically used to pause a particular        |
   |                |                                   | recurring ``monitor`` operation; for instance, it   |
   |                |                                   | can complement the respective resource being        |
   |                |                                   | unmanaged (``is-managed=false``), as this alone     |
   |                |                                   | will :ref:`not block any configured monitoring      |
   |                |                                   | <s-monitoring-unmanaged>`.  Disabling the operation |
   |                |                                   | does not suppress all actions of the given type.    |
   |                |                                   | Allowed values: ``true``, ``false``.                |
   +----------------+-----------------------------------+-----------------------------------------------------+
   | record-pending | TRUE                              | .. index::                                          |
   |                |                                   |    single: record-pending; action property          |
   |                |                                   |    single: action; property, record-pending         |
   |                |                                   |                                                     |
   |                |                                   | If ``true``, the intention to perform the operation |
   |                |                                   | is recorded so that GUIs and CLI tools can indicate |
   |                |                                   | that an operation is in progress.  This is best set |
   |                |                                   | as an *operation default*                           |
   |                |                                   | (see :ref:`s-operation-defaults`).  Allowed values: |
   |                |                                   | ``true``, ``false``.                                |
   +----------------+-----------------------------------+-----------------------------------------------------+
   | role           |                                   | .. index::                                          |
   |                |                                   |    single: role; action property                    |
   |                |                                   |    single: action; property, role                   |
   |                |                                   |                                                     |
   |                |                                   | Run the operation only on node(s) that the cluster  |
   |                |                                   | thinks should be in the specified role. This only   |
   |                |                                   | makes sense for recurring ``monitor`` operations.   |
   |                |                                   | Allowed (case-sensitive) values: ``Stopped``,       |
   |                |                                   | ``Started``, and in the case of :ref:`promotable    |
   |                |                                   | clone resources <s-resource-promotable>`,           |
   |                |                                   | ``Unpromoted`` and ``Promoted``.                    |
   +----------------+-----------------------------------+-----------------------------------------------------+

.. note::

   When ``on-fail`` is set to ``demote``, recovery from failure by a successful
   demote causes the cluster to recalculate whether and where a new instance
   should be promoted. The node with the failure is eligible, so if promotion
   scores have not changed, it will be promoted again.

   There is no direct equivalent of ``migration-threshold`` for the promoted
   role, but the same effect can be achieved with a location constraint using a
   :ref:`rule <rules>` with a node attribute expression for the resource's fail
   count.

   For example, to immediately ban the promoted role from a node with any
   failed promote or promoted instance monitor:

   .. code-block:: xml

      <rsc_location id="loc1" rsc="my_primitive">
          <rule id="rule1" score="-INFINITY" role="Promoted" boolean-op="or">
            <expression id="expr1" attribute="fail-count-my_primitive#promote_0"
              operation="gte" value="1"/>
            <expression id="expr2" attribute="fail-count-my_primitive#monitor_10000"
              operation="gte" value="1"/>
          </rule>
      </rsc_location>

   This example assumes that there is a promotable clone of the ``my_primitive``
   resource (note that the primitive name, not the clone name, is used in the
   rule), and that there is a recurring 10-second-interval monitor configured for
   the promoted role (fail count attributes specify the interval in
   milliseconds).

.. _s-resource-monitoring:

Monitoring Resources for Failure
________________________________

When Pacemaker first starts a resource, it runs one-time ``monitor`` operations
(referred to as *probes*) to ensure the resource is running where it's
supposed to be, and not running where it's not supposed to be. (This behavior
can be affected by the ``resource-discovery`` location constraint property.)

Other than those initial probes, Pacemaker will *not* (by default) check that
the resource continues to stay healthy [#]_.  You must configure ``monitor``
operations explicitly to perform these checks.

.. topic:: An OCF resource with a recurring health check

   .. code-block:: xml

      <primitive id="Public-IP" class="ocf" type="IPaddr" provider="heartbeat">
        <operations>
           <op id="Public-IP-start" name="start" timeout="60s"/>
           <op id="Public-IP-monitor" name="monitor" interval="60s"/>
        </operations>
        <instance_attributes id="params-public-ip">
           <nvpair id="public-ip-addr" name="ip" value="192.0.2.2"/>
        </instance_attributes>
      </primitive>

By default, a ``monitor`` operation will ensure that the resource is running
where it is supposed to. The ``target-role`` property can be used for further
checking.

For example, if a resource has one ``monitor`` operation with
``interval=10 role=Started`` and a second ``monitor`` operation with
``interval=11 role=Stopped``, the cluster will run the first monitor on any nodes
it thinks *should* be running the resource, and the second monitor on any nodes
that it thinks *should not* be running the resource (for the truly paranoid,
who want to know when an administrator manually starts a service by mistake).

.. note::

   Currently, monitors with ``role=Stopped`` are not implemented for
   :ref:`clone <s-resource-clone>` resources.

.. _s-monitoring-unmanaged:

Monitoring Resources When Administration is Disabled
____________________________________________________

Recurring ``monitor`` operations behave differently under various administrative
settings:

* When a resource is unmanaged (by setting ``is-managed=false``): No monitors
  will be stopped.

  If the unmanaged resource is stopped on a node where the cluster thinks it
  should be running, the cluster will detect and report that it is not, but it
  will not consider the monitor failed, and will not try to start the resource
  until it is managed again.

  Starting the unmanaged resource on a different node is strongly discouraged
  and will at least cause the cluster to consider the resource failed, and
  may require the resource's ``target-role`` to be set to ``Stopped`` then
  ``Started`` to be recovered.

* When a resource is put into maintenance mode (by setting
  ``maintenance=true``): The resource will be marked as unmanaged. (This
  overrides ``is-managed=true``.)

  Additionally, all monitor operations will be stopped, except those specifying
  ``role`` as ``Stopped`` (which will be newly initiated if appropriate). As
  with unmanaged resources in general, starting a resource on a node other than
  where the cluster expects it to be will cause problems.

* When a node is put into standby: All resources will be moved away from the
  node, and all ``monitor`` operations will be stopped on the node, except those
  specifying ``role`` as ``Stopped`` (which will be newly initiated if
  appropriate).

* When a node is put into maintenance mode: All resources that are active on the
  node will be marked as in maintenance mode. See above for more details.

* When the cluster is put into maintenance mode: All resources in the cluster
  will be marked as in maintenance mode. See above for more details.

A resource is in maintenance mode if the cluster, the node where the resource
is active, or the resource itself is configured to be in maintenance mode. If a
resource is in maintenance mode, then it is also unmanaged. However, if a
resource is unmanaged, it is not necessarily in maintenance mode.

.. _s-operation-defaults:

Setting Global Defaults for Operations
______________________________________

You can change the global default values for operation properties
in a given cluster. These are defined in an ``op_defaults`` section 
of the CIB's ``configuration`` section, and can be set with
``crm_attribute``.  For example,

.. code-block:: none

   # crm_attribute --type op_defaults --name timeout --update 20s

would default each operation's ``timeout`` to 20 seconds.  If an
operation's definition also includes a value for ``timeout``, then that
value would be used for that operation instead.

When Implicit Operations Take a Long Time
_________________________________________

The cluster will always perform a number of implicit operations: ``start``,
``stop`` and a non-recurring ``monitor`` operation used at startup to check
whether the resource is already active.  If one of these is taking too long,
then you can create an entry for them and specify a longer timeout.

.. topic:: An OCF resource with custom timeouts for its implicit actions

   .. code-block:: xml

      <primitive id="Public-IP" class="ocf" type="IPaddr" provider="heartbeat">
        <operations>
           <op id="public-ip-startup" name="monitor" interval="0" timeout="90s"/>
           <op id="public-ip-start" name="start" interval="0" timeout="180s"/>
           <op id="public-ip-stop" name="stop" interval="0" timeout="15min"/>
        </operations>
        <instance_attributes id="params-public-ip">
           <nvpair id="public-ip-addr" name="ip" value="192.0.2.2"/>
        </instance_attributes>
      </primitive>

Multiple Monitor Operations
___________________________

Provided no two operations (for a single resource) have the same name
and interval, you can have as many ``monitor`` operations as you like.
In this way, you can do a superficial health check every minute and
progressively more intense ones at higher intervals.

To tell the resource agent what kind of check to perform, you need to
provide each monitor with a different value for a common parameter.
The OCF standard creates a special parameter called ``OCF_CHECK_LEVEL``
for this purpose and dictates that it is "made available to the
resource agent without the normal ``OCF_RESKEY`` prefix".

Whatever name you choose, you can specify it by adding an
``instance_attributes`` block to the ``op`` tag. It is up to each
resource agent to look for the parameter and decide how to use it.

.. topic:: An OCF resource with two recurring health checks, performing
           different levels of checks specified via ``OCF_CHECK_LEVEL``.

   .. code-block:: xml

      <primitive id="Public-IP" class="ocf" type="IPaddr" provider="heartbeat">
         <operations>
            <op id="public-ip-health-60" name="monitor" interval="60">
               <instance_attributes id="params-public-ip-depth-60">
                  <nvpair id="public-ip-depth-60" name="OCF_CHECK_LEVEL" value="10"/>
               </instance_attributes>
            </op>
            <op id="public-ip-health-300" name="monitor" interval="300">
               <instance_attributes id="params-public-ip-depth-300">
                  <nvpair id="public-ip-depth-300" name="OCF_CHECK_LEVEL" value="20"/>
               </instance_attributes>
           </op>
         </operations>
         <instance_attributes id="params-public-ip">
             <nvpair id="public-ip-level" name="ip" value="192.0.2.2"/>
         </instance_attributes>
      </primitive>

Disabling a Monitor Operation
_____________________________

The easiest way to stop a recurring monitor is to just delete it.
However, there can be times when you only want to disable it
temporarily.  In such cases, simply add ``enabled=false`` to the
operation's definition.

.. topic:: Example of an OCF resource with a disabled health check

   .. code-block:: xml

      <primitive id="Public-IP" class="ocf" type="IPaddr" provider="heartbeat">
         <operations>
            <op id="public-ip-check" name="monitor" interval="60s" enabled="false"/>
         </operations>
         <instance_attributes id="params-public-ip">
            <nvpair id="public-ip-addr" name="ip" value="192.0.2.2"/>
         </instance_attributes>
      </primitive>

This can be achieved from the command line by executing:

.. code-block:: none

   # cibadmin --modify --xml-text '<op id="public-ip-check" enabled="false"/>'

Once you've done whatever you needed to do, you can then re-enable it with

.. code-block:: none

   # cibadmin --modify --xml-text '<op id="public-ip-check" enabled="true"/>'

.. [#] The project has two independent forks, hosted at
       https://www.nagios-plugins.org/ and https://www.monitoring-plugins.org/. Output
       from both projects' plugins is similar, so plugins from either project can be
       used with pacemaker.

.. [#] Currently, anyway. Automatic monitoring operations may be added in a future
       version of Pacemaker.
