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

The ``id``, ``name``, ``interval``, and ``role`` operation properties may be
specified only as XML attributes of the ``op`` element. Other operation
properties may be specified in any of the following ways, from highest
precedence to lowest:

* directly in the ``op`` element as an XML attribute
* in an ``nvpair`` element within a ``meta_attributes`` element within the
  ``op`` element
* in an ``nvpair`` element within a ``meta_attributes`` element within
  :ref:`operation defaults <s-operation-defaults>`

If not specified, the default from the table below is used.

.. list-table:: **Operation Properties**
   :class: longtable
   :widths: 2 2 3 4
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description
   * - .. _op_id:
       
       .. index::
          pair: op; id
          single: id; action property
          single: action; property, id
       
       id
     - :ref:`id <id>`
     - 
     - A unique identifier for the XML element *(required)*
   * - .. _op_name:
       
       .. index::
          pair: op; name
          single: name; action property
          single: action; property, name
       
       name
     - :ref:`text <text>`
     - 
     - An action name supported by the resource agent *(required)*
   * - .. _op_interval:
       
       .. index::
          pair: op; interval
          single: interval; action property
          single: action; property, interval
       
       interval
     - :ref:`duration <duration>`
     - 0
     - If this is a positive value, Pacemaker will schedule recurring instances
       of this operation at the given interval (which makes sense only with
       :ref:`name <op_name>` set to :ref:`monitor <s-resource-monitoring>`). If
       this is 0, Pacemaker will apply other properties configured for this
       operation to instances that are scheduled as needed during normal
       cluster operation. *(required)*
   * - .. _op_role:
       
       .. index::
          pair: op; role
          single: role; action property
          single: action; property, role
       
       role
     - :ref:`enumeration <enumeration>`
     - 
     - If this is set, the operation configuration applies only on nodes where
       the cluster expects the resource to be in the specified role. This makes
       sense only for recurring monitors. Allowed values: ``Started``,
       ``Stopped``, and in the case of :ref:`promotable clone resources
       <s-resource-promotable>`, ``Unpromoted`` and ``Promoted``.
   * - .. _op_timeout:
       
       .. index::
          pair: op; timeout
          single: timeout; action property
          single: action; property, timeout
       
       timeout
     - :ref:`timeout <timeout>`
     - 20s
     - If resource agent execution does not complete within this amount of
       time, the action will be considered failed. **Note:** timeouts for
       fencing agents are handled specially (see the :ref:`fencing` chapter).
   * - .. _op_on_fail:
       
       .. index::
          pair: op; on-fail
          single: on-fail; action property
          single: action; property, on-fail
       
       on-fail
     - :ref:`enumeration <enumeration>`
     - * If ``name`` is ``stop``: ``fence`` if
         :ref:`stonith-enabled <stonith_enabled>` is true, otherwise ``block``
       * If ``name`` is ``demote``: ``on-fail`` of the ``monitor`` action with
         ``role`` set to ``Promoted``, if present, enabled, and configured to a
         value other than ``demote``, or ``restart`` otherwise
       * Otherwise: ``restart``
     - How the cluster should respond to a failure of this action. Allowed
       values:
       
       * ``ignore:`` Pretend the resource did not fail
       * ``block:`` Do not perform any further operations on the resource
       * ``stop:`` Stop the resource and leave it stopped
       * ``demote:`` Demote the resource, without a full restart. This is valid
         only for ``promote`` actions, and for ``monitor`` actions with both a
         nonzero ``interval`` and ``role`` set to ``Promoted``; for any other
         action, a configuration error will be logged, and the default behavior
         will be used. *(since 2.0.5)*
       * ``restart:`` Stop the resource, and start it again if allowed
         (possibly on a different node)
       * ``fence:`` Fence the node on which the resource failed
       * ``standby:`` Put the node on which the resource failed in standby mode
         (forcing *all* resources away)
   * - .. _op_enabled:
       
       .. index::
          pair: op; enabled
          single: enabled; action property
          single: action; property, enabled
       
       enabled
     - :ref:`boolean <boolean>`
     - true
     - If ``false``, ignore this operation definition. This does not suppress
       all actions of this type, but is typically used to pause a recurring
       monitor. This can complement the resource being unmanaged
       (:ref:`is-managed <is_managed>` set to ``false``), which does not stop
       recurring operations. Maintenance mode, which does stop configured
       monitors, overrides this setting.
   * - .. _op_record_pending:
       
       .. index::
          pair: op; record-pending
          single: record-pending; action property
          single: action; property, record-pending
       
       record-pending
     - :ref:`boolean <boolean>`
     - true
     - Operation results are always recorded when the operation completes
       (successful or not). If this is ``true``, operations will also be
       recorded when initiated, so that status output can indicate that the
       operation is in progress.

.. note::

   Only one action can be configured for any given combination of ``name`` and
   ``interval``.

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


.. index::
   single: start-delay; operation attribute
   single: interval-origin; operation attribute
   single: interval; interval-origin
   single: operation; interval-origin
   single: operation; start-delay

Specifying When Recurring Actions are Performed
###############################################

By default, recurring actions are scheduled relative to when the resource
started. In some cases, you might prefer that a recurring action start relative
to a specific date and time. For example, you might schedule an in-depth
monitor to run once every 24 hours, and want it to run outside business hours.

To do this, set the operation's ``interval-origin``. The cluster uses this point
to calculate the correct ``start-delay`` such that the operation will occur
at ``interval-origin`` plus a multiple of the operation interval.

For example, if the recurring operation's interval is 24h, its
``interval-origin`` is set to 02:00, and it is currently 14:32, then the
cluster would initiate the operation after 11 hours and 28 minutes.

The value specified for ``interval`` and ``interval-origin`` can be any
date/time conforming to the
`ISO8601 standard <https://en.wikipedia.org/wiki/ISO_8601>`_. By way of
example, to specify an operation that would run on the first Monday of
2021 and every Monday after that, you would add:

.. topic:: Example recurring action that runs relative to base date/time

   .. code-block:: xml

      <op id="intensive-monitor" name="monitor" interval="P7D" interval-origin="2021-W01-1"/>


.. index::
   single: resource; failure recovery
   single: operation; failure recovery

.. _failure-handling:

Handling Resource Failure
#########################

By default, Pacemaker will attempt to recover failed resources by restarting
them. However, failure recovery is highly configurable.

.. index::
   single: resource; failure count
   single: operation; failure count

Failure Counts
______________

Pacemaker tracks resource failures for each combination of node, resource, and
operation (start, stop, monitor, etc.).

You can query the fail count for a particular node, resource, and/or operation
using the ``crm_failcount`` command. For example, to see how many times the
10-second monitor for ``myrsc`` has failed on ``node1``, run:

.. code-block:: none

   # crm_failcount --query -r myrsc -N node1 -n monitor -I 10s

If you omit the node, ``crm_failcount`` will use the local node. If you omit
the operation and interval, ``crm_failcount`` will display the sum of the fail
counts for all operations on the resource.

You can use ``crm_resource --cleanup`` or ``crm_failcount --delete`` to clear
fail counts. For example, to clear the above monitor failures, run:

.. code-block:: none

   # crm_resource --cleanup -r myrsc -N node1 -n monitor -I 10s

If you omit the resource, ``crm_resource --cleanup`` will clear failures for
all resources. If you omit the node, it will clear failures on all nodes. If
you omit the operation and interval, it will clear the failures for all
operations on the resource.

.. note::

   Even when cleaning up only a single operation, all failed operations will
   disappear from the status display. This allows us to trigger a re-check of
   the resource's current status.

Higher-level tools may provide other commands for querying and clearing
fail counts.

The ``crm_mon`` tool shows the current cluster status, including any failed
operations. To see the current fail counts for any failed resources, call
``crm_mon`` with the ``--failcounts`` option. This shows the fail counts per
resource (that is, the sum of any operation fail counts for the resource).

.. index::
   single: migration-threshold; resource meta-attribute
   single: resource; migration-threshold

Failure Response
________________

Normally, if a running resource fails, pacemaker will try to stop it and start
it again. Pacemaker will choose the best location to start it each time, which
may be the same node that it failed on.

However, if a resource fails repeatedly, it is possible that there is an
underlying problem on that node, and you might desire trying a different node
in such a case. Pacemaker allows you to set your preference via the
``migration-threshold`` resource meta-attribute. [#]_

If you define ``migration-threshold`` to *N* for a resource, it will be banned
from the original node after *N* failures there.

.. note::

   The ``migration-threshold`` is per *resource*, even though fail counts are
   tracked per *operation*. The operation fail counts are added together
   to compare against the ``migration-threshold``.

By default, fail counts remain until manually cleared by an administrator
using ``crm_resource --cleanup`` or ``crm_failcount --delete`` (hopefully after
first fixing the failure's cause). It is possible to have fail counts expire
automatically by setting the ``failure-timeout`` resource meta-attribute.

.. important::

   A successful operation does not clear past failures. If a recurring monitor
   operation fails once, succeeds many times, then fails again days later, its
   fail count is 2. Fail counts are cleared only by manual intervention or
   failure timeout.

For example, setting ``migration-threshold`` to 2 and ``failure-timeout`` to
``60s`` would cause the resource to move to a new node after 2 failures, and
allow it to move back (depending on stickiness and constraint scores) after one
minute.

.. note::

   ``failure-timeout`` is measured since the most recent failure. That is, older
   failures do not individually time out and lower the fail count. Instead, all
   failures are timed out simultaneously (and the fail count is reset to 0) if
   there is no new failure for the timeout period.

There are two exceptions to the migration threshold: when a resource either
fails to start or fails to stop.

If the cluster property ``start-failure-is-fatal`` is set to ``true`` (which is
the default), start failures cause the fail count to be set to ``INFINITY`` and
thus always cause the resource to move immediately.

Stop failures are slightly different and crucial.  If a resource fails to stop
and fencing is enabled, then the cluster will fence the node in order to be
able to start the resource elsewhere.  If fencing is disabled, then the cluster
has no way to continue and will not try to start the resource elsewhere, but
will try to stop it again after any failure timeout or clearing.


.. index::
   single: reload
   single: reload-agent

Reloading an Agent After a Definition Change
############################################

The cluster automatically detects changes to the configuration of active
resources. The cluster's normal response is to stop the service (using the old
definition) and start it again (with the new definition). This works, but some
resource agents are smarter and can be told to use a new set of options without
restarting.

To take advantage of this capability, the resource agent must:

* Implement the ``reload-agent`` action. What it should do depends completely
  on your application!

  .. note::

     Resource agents may also implement a ``reload`` action to make the managed
     service reload its own *native* configuration. This is different from
     ``reload-agent``, which makes effective changes in the resource's
     *Pacemaker* configuration (specifically, the values of the agent's
     reloadable parameters).

* Advertise the ``reload-agent`` operation in the ``actions`` section of its
  meta-data.

* Set the ``reloadable`` attribute to 1 in the ``parameters`` section of
  its meta-data for any parameters eligible to be reloaded after a change.

Once these requirements are satisfied, the cluster will automatically know to
reload the resource (instead of restarting) when a reloadable parameter
changes.

.. note::

   Metadata will not be re-read unless the resource needs to be started. If you
   edit the agent of an already active resource to set a parameter reloadable,
   the resource may restart the first time the parameter value changes.

.. note::

   If both a reloadable and non-reloadable parameter are changed
   simultaneously, the resource will be restarted.



.. _live-migration:

Migrating Resources
###################

Normally, when the cluster needs to move a resource, it fully restarts the
resource (that is, it stops the resource on the current node and starts it on
the new node).

However, some types of resources, such as many virtual machines, are able to
move to another location without loss of state (often referred to as live
migration or hot migration). In pacemaker, this is called live migration.
Pacemaker can be configured to migrate a resource when moving it, rather than
restarting it.

Not all resources are able to migrate; see the
:ref:`migration checklist <migration_checklist>` below. Even those that can,
won't do so in all situations. Conceptually, there are two requirements from
which the other prerequisites follow:

* The resource must be active and healthy at the old location; and
* everything required for the resource to run must be available on both the old
  and new locations.

The cluster is able to accommodate both *push* and *pull* migration models by
requiring the resource agent to support two special actions: ``migrate_to``
(performed on the current location) and ``migrate_from`` (performed on the
destination).

In push migration, the process on the current location transfers the resource
to the new location where is it later activated. In this scenario, most of the
work would be done in the ``migrate_to`` action and, if anything, the
activation would occur during ``migrate_from``.

Conversely for pull, the ``migrate_to`` action is practically empty and
``migrate_from`` does most of the work, extracting the relevant resource state
from the old location and activating it.

There is no wrong or right way for a resource agent to implement migration, as
long as it works.

.. _migration_checklist:

.. topic:: Migration Checklist

   * The resource may not be a clone.
   * The resource agent standard must be OCF.
   * The resource must not be in a failed or degraded state.
   * The resource agent must support ``migrate_to`` and ``migrate_from``
     actions, and advertise them in its meta-data.
   * The resource must have the ``allow-migrate`` meta-attribute set to
     ``true`` (which is not the default).

If an otherwise migratable resource depends on another resource via an ordering
constraint, there are special situations in which it will be restarted rather
than migrated.

For example, if the resource depends on a clone, and at the time the resource
needs to be moved, the clone has instances that are stopping and instances that
are starting, then the resource will be restarted. The scheduler is not yet
able to model this situation correctly and so takes the safer (if less optimal)
path.

Also, if a migratable resource depends on a non-migratable resource, and both
need to be moved, the migratable resource will be restarted.

.. rubric:: Footnotes

.. [#] Currently, anyway. Automatic monitoring operations may be added in a future
       version of Pacemaker.

.. [#] The naming of this option was perhaps unfortunate as it is easily
       confused with live migration, the process of moving a resource from one
       node to another without stopping it.  Xen virtual guests are the most
       common example of resources that can be migrated in this manner.
