.. index::
   single: resource; action
   single: resource; operation

.. _operation:

Resource Operations
-------------------

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
####################

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
################################

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
####################################################

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
######################################

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
#########################################

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
###########################

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
#############################

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

.. [#] Currently, anyway. Automatic monitoring operations may be added in a future
       version of Pacemaker.
