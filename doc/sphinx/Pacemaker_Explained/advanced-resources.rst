Advanced Resource Types
-----------------------

.. index:
   single: group resource
   single: resource; group

.. _group-resources:

Groups - A Syntactic Shortcut
#############################

One of the most common elements of a cluster is a set of resources
that need to be located together, start sequentially, and stop in the
reverse order.  To simplify this configuration, we support the concept
of groups.
   
.. topic:: A group of two primitive resources

   .. code-block:: xml

      <group id="shortcut">
         <primitive id="Public-IP" class="ocf" type="IPaddr" provider="heartbeat">
          <instance_attributes id="params-public-ip">
             <nvpair id="public-ip-addr" name="ip" value="192.0.2.2"/>
          </instance_attributes>
         </primitive>
         <primitive id="Email" class="lsb" type="exim"/>
      </group> 
   
Although the example above contains only two resources, there is no
limit to the number of resources a group can contain.  The example is
also sufficient to explain the fundamental properties of a group:
   
* Resources are started in the order they appear in (**Public-IP** first,
  then **Email**)
* Resources are stopped in the reverse order to which they appear in
  (**Email** first, then **Public-IP**)
   
If a resource in the group can't run anywhere, then nothing after that
is allowed to run, too.
   
* If **Public-IP** can't run anywhere, neither can **Email**;
* but if **Email** can't run anywhere, this does not affect **Public-IP**
  in any way
   
The group above is logically equivalent to writing:
   
.. topic:: How the cluster sees a group resource

   .. code-block:: xml

      <configuration>
         <resources>
          <primitive id="Public-IP" class="ocf" type="IPaddr" provider="heartbeat">
           <instance_attributes id="params-public-ip">
              <nvpair id="public-ip-addr" name="ip" value="192.0.2.2"/>
           </instance_attributes>
          </primitive>
          <primitive id="Email" class="lsb" type="exim"/>
         </resources>
         <constraints>
            <rsc_colocation id="xxx" rsc="Email" with-rsc="Public-IP" score="INFINITY"/>
            <rsc_order id="yyy" first="Public-IP" then="Email"/>
         </constraints>
      </configuration> 

Obviously as the group grows bigger, the reduced configuration effort
can become significant.

Another (typical) example of a group is a DRBD volume, the filesystem
mount, an IP address, and an application that uses them.

.. index::
   pair: XML element; group

Group Properties
________________

.. table:: **Properties of a Group Resource**
   :widths: 1 4

   +-------+--------------------------------------+
   | Field | Description                          |
   +=======+======================================+
   | id    | .. index::                           |
   |       |    single: group; property, id       |
   |       |    single: property; id (group)      |
   |       |    single: id; group property        |
   |       |                                      |
   |       | A unique name for the group          |
   +-------+--------------------------------------+

Group Options
_____________

Groups inherit the ``priority``, ``target-role``, and ``is-managed`` properties
from primitive resources. See :ref:`resource_options` for information about
those properties.
   
.. table:: **Group-specific configuration options**
   :class: longtable
   :widths: 1 1 3

   +-------------------+-----------------+-------------------------------------------------------+
   | Meta-Attribute    | Default         | Description                                           |
   +===================+=================+=======================================================+
   | ordered           | true            |  .. index::                                           |
   |                   |                 |     single: group; option, ordered                    |
   |                   |                 |     single: option; ordered (group)                   |
   |                   |                 |     single: ordered; group option                     |
   |                   |                 |                                                       |
   |                   |                 | If **true**, group members will be started in the     |
   |                   |                 | order they are listed in the configuration (and       |
   |                   |                 | stopped in the reverse order).                        |
   +-------------------+-----------------+-------------------------------------------------------+

Group Instance Attributes
_________________________

Groups have no instance attributes. However, any that are set for the group
object will be inherited by the group's children.
   
Group Contents
______________

Groups may only contain a collection of cluster resources (see
:ref:`primitive-resource`).  To refer to a child of a group resource, just use
the child's ``id`` instead of the group's.
   
Group Constraints
_________________
   
Although it is possible to reference a group's children in
constraints, it is usually preferable to reference the group itself.
   
.. topic:: Some constraints involving groups

   .. code-block:: xml

      <constraints>
          <rsc_location id="group-prefers-node1" rsc="shortcut" node="node1" score="500"/>
          <rsc_colocation id="webserver-with-group" rsc="Webserver" with-rsc="shortcut"/>
          <rsc_order id="start-group-then-webserver" first="Webserver" then="shortcut"/>
      </constraints> 

.. index::
   pair: resource-stickiness; group

Group Stickiness
________________
   
Stickiness, the measure of how much a resource wants to stay where it
is, is additive in groups.  Every active resource of the group will
contribute its stickiness value to the group's total.  So if the
default ``resource-stickiness`` is 100, and a group has seven members,
five of which are active, then the group as a whole will prefer its
current location with a score of 500.

.. index::
   single: clone
   single: resource; clone
   
.. _s-resource-clone:

Clones - Resources That Can Have Multiple Active Instances
##########################################################

*Clone* resources are resources that can have more than one copy active at the
same time. This allows you, for example, to run a copy of a daemon on every
node. You can clone any primitive or group resource [#]_.
   
Anonymous versus Unique Clones
______________________________
   
A clone resource is configured to be either *anonymous* or *globally unique*.
   
Anonymous clones are the simplest. These behave completely identically
everywhere they are running. Because of this, there can be only one instance of
an anonymous clone active per node.
         
The instances of globally unique clones are distinct entities. All instances
are launched identically, but one instance of the clone is not identical to any
other instance, whether running on the same node or a different node. As an
example, a cloned IP address can use special kernel functionality such that
each instance handles a subset of requests for the same IP address.

.. index::
   single: promotable clone
   single: resource; promotable

.. _s-resource-promotable:

Promotable clones
_________________

If a clone is *promotable*, its instances can perform a special role that
Pacemaker will manage via the ``promote`` and ``demote`` actions of the resource
agent.

Services that support such a special role have various terms for the special
role and the default role: primary and secondary, master and replica,
controller and worker, etc. Pacemaker uses the terms *promoted* and
*unpromoted* to be agnostic to what the service calls them or what they do.
   
All that Pacemaker cares about is that an instance comes up in the unpromoted role
when started, and the resource agent supports the ``promote`` and ``demote`` actions
to manage entering and exiting the promoted role.

.. index::
   pair: XML element; clone
   
Clone Properties
________________
   
.. table:: **Properties of a Clone Resource**
   :widths: 1 4

   +-------+--------------------------------------+
   | Field | Description                          |
   +=======+======================================+
   | id    | .. index::                           |
   |       |    single: clone; property, id       |
   |       |    single: property; id (clone)      |
   |       |    single: id; clone property        |
   |       |                                      |
   |       | A unique name for the clone          |
   +-------+--------------------------------------+

.. index::
   pair: options; clone

Clone Options
_____________

:ref:`Options <resource_options>` inherited from primitive resources:
``priority, target-role, is-managed``
   
.. table:: **Clone-specific configuration options**
   :class: longtable
   :widths: 1 1 3

   +-------------------+-----------------+-------------------------------------------------------+
   | Field             | Default         | Description                                           |
   +===================+=================+=======================================================+
   | globally-unique   | false           |  .. index::                                           |
   |                   |                 |     single: clone; option, globally-unique            |
   |                   |                 |     single: option; globally-unique (clone)           |
   |                   |                 |     single: globally-unique; clone option             |
   |                   |                 |                                                       |
   |                   |                 | If **true**, each clone instance performs a           |
   |                   |                 | distinct function                                     |
   +-------------------+-----------------+-------------------------------------------------------+
   | clone-max         | 0               | .. index::                                            |
   |                   |                 |    single: clone; option, clone-max                   |
   |                   |                 |    single: option; clone-max (clone)                  |
   |                   |                 |    single: clone-max; clone option                    |
   |                   |                 |                                                       |
   |                   |                 | The maximum number of clone instances that can        |
   |                   |                 | be started across the entire cluster. If 0, the       |
   |                   |                 | number of nodes in the cluster will be used.          |
   +-------------------+-----------------+-------------------------------------------------------+
   | clone-node-max    | 1               | .. index::                                            |
   |                   |                 |    single: clone; option, clone-node-max              |
   |                   |                 |    single: option; clone-node-max (clone)             |
   |                   |                 |    single: clone-node-max; clone option               |
   |                   |                 |                                                       |
   |                   |                 | If ``globally-unique`` is **true**, the maximum       |
   |                   |                 | number of clone instances that can be started         |
   |                   |                 | on a single node                                      |
   +-------------------+-----------------+-------------------------------------------------------+
   | clone-min         | 0               | .. index::                                            |
   |                   |                 |    single: clone; option, clone-min                   |
   |                   |                 |    single: option; clone-min (clone)                  |
   |                   |                 |    single: clone-min; clone option                    |
   |                   |                 |                                                       |
   |                   |                 | Require at least this number of clone instances       |
   |                   |                 | to be runnable before allowing resources              |
   |                   |                 | depending on the clone to be runnable. A value        |
   |                   |                 | of 0 means require all clone instances to be          |
   |                   |                 | runnable.                                             |
   +-------------------+-----------------+-------------------------------------------------------+
   | notify            | false           | .. index::                                            |
   |                   |                 |    single: clone; option, notify                      |
   |                   |                 |    single: option; notify (clone)                     |
   |                   |                 |    single: notify; clone option                       |
   |                   |                 |                                                       |
   |                   |                 | Call the resource agent's **notify** action for       |
   |                   |                 | all active instances, before and after starting       |
   |                   |                 | or stopping any clone instance. The resource          |
   |                   |                 | agent must support this action.                       |
   |                   |                 | Allowed values: **false**, **true**                   |
   +-------------------+-----------------+-------------------------------------------------------+
   | ordered           | false           | .. index::                                            |
   |                   |                 |    single: clone; option, ordered                     |
   |                   |                 |    single: option; ordered (clone)                    |
   |                   |                 |    single: ordered; clone option                      |
   |                   |                 |                                                       |
   |                   |                 | If **true**, clone instances must be started          |
   |                   |                 | sequentially instead of in parallel.                  |
   |                   |                 | Allowed values: **false**, **true**                   |
   +-------------------+-----------------+-------------------------------------------------------+
   | interleave        | false           | .. index::                                            |
   |                   |                 |    single: clone; option, interleave                  |
   |                   |                 |    single: option; interleave (clone)                 |
   |                   |                 |    single: interleave; clone option                   |
   |                   |                 |                                                       |
   |                   |                 | When this clone is ordered relative to another        |
   |                   |                 | clone, if this option is **false** (the default),     |
   |                   |                 | the ordering is relative to *all* instances of        |
   |                   |                 | the other clone, whereas if this option is            |
   |                   |                 | **true**, the ordering is relative only to            |
   |                   |                 | instances on the same node.                           |
   |                   |                 | Allowed values: **false**, **true**                   |
   +-------------------+-----------------+-------------------------------------------------------+
   | promotable        | false           | .. index::                                            |
   |                   |                 |    single: clone; option, promotable                  |
   |                   |                 |    single: option; promotable (clone)                 |
   |                   |                 |    single: promotable; clone option                   |
   |                   |                 |                                                       |
   |                   |                 | If **true**, clone instances can perform a            |
   |                   |                 | special role that Pacemaker will manage via the       |
   |                   |                 | resource agent's **promote** and **demote**           |
   |                   |                 | actions. The resource agent must support these        |
   |                   |                 | actions.                                              |
   |                   |                 | Allowed values: **false**, **true**                   |
   +-------------------+-----------------+-------------------------------------------------------+
   | promoted-max      | 1               | .. index::                                            |
   |                   |                 |    single: clone; option, promoted-max                |
   |                   |                 |    single: option; promoted-max (clone)               |
   |                   |                 |    single: promoted-max; clone option                 |
   |                   |                 |                                                       |
   |                   |                 | If ``promotable`` is **true**, the number of          |
   |                   |                 | instances that can be promoted at one time            |
   |                   |                 | across the entire cluster                             |
   +-------------------+-----------------+-------------------------------------------------------+
   | promoted-node-max | 1               | .. index::                                            |
   |                   |                 |    single: clone; option, promoted-node-max           |
   |                   |                 |    single: option; promoted-node-max (clone)          |
   |                   |                 |    single: promoted-node-max; clone option            |
   |                   |                 |                                                       |
   |                   |                 | If ``promotable`` is **true** and ``globally-unique`` |
   |                   |                 | is **false**, the number of clone instances can be    |
   |                   |                 | promoted at one time on a single node                 |
   +-------------------+-----------------+-------------------------------------------------------+
   
.. note:: **Deprecated Terminology**

   In older documentation and online examples, you may see promotable clones
   referred to as *multi-state*, *stateful*, or *master/slave*; these mean the
   same thing as *promotable*. Certain syntax is supported for backward
   compatibility, but is deprecated and will be removed in a future version:

   * Using a ``master`` tag, instead of a ``clone`` tag with the ``promotable``
     meta-attribute set to ``true``
   * Using the ``master-max`` meta-attribute instead of ``promoted-max``
   * Using the ``master-node-max`` meta-attribute instead of
     ``promoted-node-max``
   * Using ``Master`` as a role name instead of ``Promoted``
   * Using ``Slave`` as a role name instead of ``Unpromoted``

   
Clone Contents
______________
   
Clones must contain exactly one primitive or group resource.
   
.. topic:: A clone that runs a web server on all nodes

   .. code-block:: xml

      <clone id="apache-clone">
          <primitive id="apache" class="lsb" type="apache">
              <operations>
                 <op id="apache-monitor" name="monitor" interval="30"/>
              </operations>
          </primitive>
      </clone> 

.. warning::

   You should never reference the name of a clone's child (the primitive or group
   resource being cloned). If you think you need to do this, you probably need to
   re-evaluate your design.
   
Clone Instance Attribute
________________________
   
Clones have no instance attributes; however, any that are set here will be
inherited by the clone's child.
   
.. index::
   single: clone; constraint

Clone Constraints
_________________
   
In most cases, a clone will have a single instance on each active cluster
node.  If this is not the case, you can indicate which nodes the
cluster should preferentially assign copies to with resource location
constraints.  These constraints are written no differently from those
for primitive resources except that the clone's **id** is used.
   
.. topic:: Some constraints involving clones

   .. code-block:: xml

      <constraints>
          <rsc_location id="clone-prefers-node1" rsc="apache-clone" node="node1" score="500"/>
          <rsc_colocation id="stats-with-clone" rsc="apache-stats" with="apache-clone"/>
          <rsc_order id="start-clone-then-stats" first="apache-clone" then="apache-stats"/>
      </constraints> 
   
Ordering constraints behave slightly differently for clones.  In the
example above, ``apache-stats`` will wait until all copies of ``apache-clone``
that need to be started have done so before being started itself.
Only if *no* copies can be started will ``apache-stats`` be prevented
from being active.  Additionally, the clone will wait for
``apache-stats`` to be stopped before stopping itself.

Colocation of a primitive or group resource with a clone means that
the resource can run on any node with an active instance of the clone.
The cluster will choose an instance based on where the clone is running and
the resource's own location preferences.

Colocation between clones is also possible.  If one clone **A** is colocated
with another clone **B**, the set of allowed locations for **A** is limited to
nodes on which **B** is (or will be) active.  Placement is then performed
normally.
   
.. index::
   single: promotable clone; constraint

.. _promotable-clone-constraints:

Promotable Clone Constraints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   
For promotable clone resources, the ``first-action`` and/or ``then-action`` fields
for ordering constraints may be set to ``promote`` or ``demote`` to constrain the
promoted role, and colocation constraints may contain ``rsc-role`` and/or
``with-rsc-role`` fields.

.. topic:: Constraints involving promotable clone resources       

   .. code-block:: xml

      <constraints>
         <rsc_location id="db-prefers-node1" rsc="database" node="node1" score="500"/>
         <rsc_colocation id="backup-with-db-unpromoted" rsc="backup"
           with-rsc="database" with-rsc-role="Unpromoted"/>
         <rsc_colocation id="myapp-with-db-promoted" rsc="myApp"
           with-rsc="database" with-rsc-role="Promoted"/>
         <rsc_order id="start-db-before-backup" first="database" then="backup"/>
         <rsc_order id="promote-db-then-app" first="database" first-action="promote"
           then="myApp" then-action="start"/>
      </constraints> 

In the example above, **myApp** will wait until one of the database
copies has been started and promoted before being started
itself on the same node.  Only if no copies can be promoted will **myApp** be
prevented from being active.  Additionally, the cluster will wait for
**myApp** to be stopped before demoting the database.

Colocation of a primitive or group resource with a promotable clone
resource means that it can run on any node with an active instance of
the promotable clone resource that has the specified role (``Promoted`` or
``Unpromoted``).  In the example above, the cluster will choose a location
based on where database is running in the promoted role, and if there are
multiple promoted instances it will also factor in **myApp**'s own location
preferences when deciding which location to choose.

Colocation with regular clones and other promotable clone resources is also
possible.  In such cases, the set of allowed locations for the **rsc**
clone is (after role filtering) limited to nodes on which the
``with-rsc`` promotable clone resource is (or will be) in the specified role.
Placement is then performed as normal.
   
Using Promotable Clone Resources in Colocation Sets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a promotable clone is used in a :ref:`resource set <s-resource-sets>`
inside a colocation constraint, the resource set may take a ``role`` attribute.

In the following example, an instance of **B** may be promoted only on a node
where **A** is in the promoted role. Additionally, resources **C** and **D**
must be located on a node where both **A** and **B** are promoted.
   
.. topic:: Colocate C and D with A's and B's promoted instances

   .. code-block:: xml

      <constraints>
          <rsc_colocation id="coloc-1" score="INFINITY" >
            <resource_set id="colocated-set-example-1" sequential="true" role="Promoted">
              <resource_ref id="A"/>
              <resource_ref id="B"/>
            </resource_set>
            <resource_set id="colocated-set-example-2" sequential="true">
              <resource_ref id="C"/>
              <resource_ref id="D"/>
            </resource_set>
          </rsc_colocation>
      </constraints>
   
Using Promotable Clone Resources in Ordered Sets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a promotable clone is used in a :ref:`resource set <s-resource-sets>`
inside an ordering constraint, the resource set may take an ``action``
attribute.

.. topic:: Start C and D after first promoting A and B

   .. code-block:: xml

      <constraints>
          <rsc_order id="order-1" score="INFINITY" >
            <resource_set id="ordered-set-1" sequential="true" action="promote">
              <resource_ref id="A"/>
              <resource_ref id="B"/>
            </resource_set>
            <resource_set id="ordered-set-2" sequential="true" action="start">
              <resource_ref id="C"/>
              <resource_ref id="D"/>
            </resource_set>
          </rsc_order>
      </constraints>
   
In the above example, **B** cannot be promoted until **A** has been promoted.
Additionally, resources **C** and **D** must wait until **A** and **B** have
been promoted before they can start.

.. index::
   pair: resource-stickiness; clone
   
.. _s-clone-stickiness:

Clone Stickiness
________________
   
To achieve a stable allocation pattern, clones are slightly sticky by
default.  If no value for ``resource-stickiness`` is provided, the clone
will use a value of 1.  Being a small value, it causes minimal
disturbance to the score calculations of other resources but is enough
to prevent Pacemaker from needlessly moving copies around the cluster.
   
.. note::

   For globally unique clones, this may result in multiple instances of the
   clone staying on a single node, even after another eligible node becomes
   active (for example, after being put into standby mode then made active again).
   If you do not want this behavior, specify a ``resource-stickiness`` of 0
   for the clone temporarily and let the cluster adjust, then set it back
   to 1 if you want the default behavior to apply again.
   
.. important::

   If ``resource-stickiness`` is set in the ``rsc_defaults`` section, it will
   apply to clone instances as well. This means an explicit ``resource-stickiness``
   of 0 in ``rsc_defaults`` works differently from the implicit default used when
   ``resource-stickiness`` is not specified.
   
Clone Resource Agent Requirements
_________________________________
   
Any resource can be used as an anonymous clone, as it requires no
additional support from the resource agent.  Whether it makes sense to
do so depends on your resource and its resource agent.
   
Resource Agent Requirements for Globally Unique Clones
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   
Globally unique clones require additional support in the resource agent. In
particular, it must only respond with ``${OCF_SUCCESS}`` if the node has that
exact instance active. All other probes for instances of the clone should
result in ``${OCF_NOT_RUNNING}`` (or one of the other OCF error codes if
they are failed).

Individual instances of a clone are identified by appending a colon and a
numerical offset, e.g. **apache:2**.

Resource agents can find out how many copies there are by examining
the ``OCF_RESKEY_CRM_meta_clone_max`` environment variable and which
instance it is by examining ``OCF_RESKEY_CRM_meta_clone``.

The resource agent must not make any assumptions (based on
``OCF_RESKEY_CRM_meta_clone``) about which numerical instances are active.  In
particular, the list of active copies will not always be an unbroken
sequence, nor always start at 0.
   
Resource Agent Requirements for Promotable Clones
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Promotable clone resources require two extra actions, ``demote`` and ``promote``,
which are responsible for changing the state of the resource. Like **start** and
**stop**, they should return ``${OCF_SUCCESS}`` if they completed successfully or
a relevant error code if they did not.

The states can mean whatever you wish, but when the resource is
started, it must come up in the unpromoted role. From there, the
cluster will decide which instances to promote.

In addition to the clone requirements for monitor actions, agents must
also *accurately* report which state they are in.  The cluster relies
on the agent to report its status (including role) accurately and does
not indicate to the agent what role it currently believes it to be in.
   
.. table:: **Role implications of OCF return codes**
   :widths: 1 3

   +----------------------+--------------------------------------------------+
   | Monitor Return Code  | Description                                      |
   +======================+==================================================+
   | OCF_NOT_RUNNING      | .. index::                                       |
   |                      |    single: OCF_NOT_RUNNING                       |
   |                      |    single: OCF return code; OCF_NOT_RUNNING      |
   |                      |                                                  |
   |                      | Stopped                                          |
   +----------------------+--------------------------------------------------+
   | OCF_SUCCESS          | .. index::                                       |
   |                      |    single: OCF_SUCCESS                           |
   |                      |    single: OCF return code; OCF_SUCCESS          |
   |                      |                                                  |
   |                      | Running (Unpromoted)                             |
   +----------------------+--------------------------------------------------+
   | OCF_RUNNING_PROMOTED | .. index::                                       |
   |                      |    single: OCF_RUNNING_PROMOTED                  |
   |                      |    single: OCF return code; OCF_RUNNING_PROMOTED |
   |                      |                                                  |
   |                      | Running (Promoted)                               |
   +----------------------+--------------------------------------------------+
   | OCF_FAILED_PROMOTED  | .. index::                                       |
   |                      |    single: OCF_FAILED_PROMOTED                   |
   |                      |    single: OCF return code; OCF_FAILED_PROMOTED  |
   |                      |                                                  |
   |                      | Failed (Promoted)                                |
   +----------------------+--------------------------------------------------+
   | Other                | .. index::                                       |
   |                      |    single: return code                           |
   |                      |                                                  |
   |                      | Failed (Unpromoted)                              |
   +----------------------+--------------------------------------------------+
   
Clone Notifications
~~~~~~~~~~~~~~~~~~~
   
If the clone has the ``notify`` meta-attribute set to **true**, and the resource
agent supports the ``notify`` action, Pacemaker will call the action when
appropriate, passing a number of extra variables which, when combined with
additional context, can be used to calculate the current state of the cluster
and what is about to happen to it.

.. index::
   single: clone; environment variables
   single: notify; environment variables
   
.. table:: **Environment variables supplied with Clone notify actions**
   :widths: 1 1

   +----------------------------------------------+-------------------------------------------------------------------------------+
   | Variable                                     | Description                                                                   |
   +==============================================+===============================================================================+
   | OCF_RESKEY_CRM_meta_notify_type              | .. index::                                                                    |
   |                                              |    single: environment variable; OCF_RESKEY_CRM_meta_notify_type              |
   |                                              |    single: OCF_RESKEY_CRM_meta_notify_type                                    |
   |                                              |                                                                               |
   |                                              | Allowed values: **pre**, **post**                                             |
   +----------------------------------------------+-------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_operation         | .. index::                                                                    |
   |                                              |    single: environment variable; OCF_RESKEY_CRM_meta_notify_operation         |
   |                                              |    single: OCF_RESKEY_CRM_meta_notify_operation                               |
   |                                              |                                                                               |
   |                                              | Allowed values: **start**, **stop**                                           |
   +----------------------------------------------+-------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_start_resource    | .. index::                                                                    |
   |                                              |    single: environment variable; OCF_RESKEY_CRM_meta_notify_start_resource    |
   |                                              |    single: OCF_RESKEY_CRM_meta_notify_start_resource                          |
   |                                              |                                                                               |
   |                                              | Resources to be started                                                       |
   +----------------------------------------------+-------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_stop_resource     | .. index::                                                                    |
   |                                              |    single: environment variable; OCF_RESKEY_CRM_meta_notify_stop_resource     |
   |                                              |    single: OCF_RESKEY_CRM_meta_notify_stop_resource                           |
   |                                              |                                                                               |
   |                                              | Resources to be stopped                                                       |
   +----------------------------------------------+-------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_active_resource   | .. index::                                                                    |
   |                                              |    single: environment variable; OCF_RESKEY_CRM_meta_notify_active_resource   |
   |                                              |    single: OCF_RESKEY_CRM_meta_notify_active_resource                         |
   |                                              |                                                                               |
   |                                              | Resources that are running                                                    |
   +----------------------------------------------+-------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_inactive_resource | .. index::                                                                    |
   |                                              |    single: environment variable; OCF_RESKEY_CRM_meta_notify_inactive_resource |
   |                                              |    single: OCF_RESKEY_CRM_meta_notify_inactive_resource                       |
   |                                              |                                                                               |
   |                                              | Resources that are not running                                                |
   +----------------------------------------------+-------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_start_uname       | .. index::                                                                    |
   |                                              |    single: environment variable; OCF_RESKEY_CRM_meta_notify_start_uname       |
   |                                              |    single: OCF_RESKEY_CRM_meta_notify_start_uname                             |
   |                                              |                                                                               |
   |                                              | Nodes on which resources will be started                                      |
   +----------------------------------------------+-------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_stop_uname        | .. index::                                                                    |
   |                                              |    single: environment variable; OCF_RESKEY_CRM_meta_notify_stop_uname        |
   |                                              |    single: OCF_RESKEY_CRM_meta_notify_stop_uname                              |
   |                                              |                                                                               |
   |                                              | Nodes on which resources will be stopped                                      |
   +----------------------------------------------+-------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_active_uname      | .. index::                                                                    |
   |                                              |    single: environment variable; OCF_RESKEY_CRM_meta_notify_active_uname      |
   |                                              |    single: OCF_RESKEY_CRM_meta_notify_active_uname                            |
   |                                              |                                                                               |
   |                                              | Nodes on which resources are running                                          |
   +----------------------------------------------+-------------------------------------------------------------------------------+

The variables come in pairs, such as
``OCF_RESKEY_CRM_meta_notify_start_resource`` and
``OCF_RESKEY_CRM_meta_notify_start_uname``, and should be treated as an
array of whitespace-separated elements.

``OCF_RESKEY_CRM_meta_notify_inactive_resource`` is an exception, as the
matching **uname** variable does not exist since inactive resources
are not running on any node.

Thus, in order to indicate that **clone:0** will be started on **sles-1**,
**clone:2** will be started on **sles-3**, and **clone:3** will be started
on **sles-2**, the cluster would set:
   
.. topic:: Notification variables

   .. code-block:: none

      OCF_RESKEY_CRM_meta_notify_start_resource="clone:0 clone:2 clone:3"
      OCF_RESKEY_CRM_meta_notify_start_uname="sles-1 sles-3 sles-2"

.. note::

   Pacemaker will log but otherwise ignore failures of notify actions.
   
Interpretation of Notification Variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   
**Pre-notification (stop):**
   
* Active resources: ``$OCF_RESKEY_CRM_meta_notify_active_resource``
* Inactive resources: ``$OCF_RESKEY_CRM_meta_notify_inactive_resource``
* Resources to be started: ``$OCF_RESKEY_CRM_meta_notify_start_resource``
* Resources to be stopped: ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
   
**Post-notification (stop) / Pre-notification (start):**
   
* Active resources

    * ``$OCF_RESKEY_CRM_meta_notify_active_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_stop_resource``

* Inactive resources

    * ``$OCF_RESKEY_CRM_meta_notify_inactive_resource``
    * plus ``$OCF_RESKEY_CRM_meta_notify_stop_resource`` 

* Resources that were started: ``$OCF_RESKEY_CRM_meta_notify_start_resource``
* Resources that were stopped: ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
   
**Post-notification (start):**
   
* Active resources:

    * ``$OCF_RESKEY_CRM_meta_notify_active_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
    * plus ``$OCF_RESKEY_CRM_meta_notify_start_resource``

* Inactive resources:

    * ``$OCF_RESKEY_CRM_meta_notify_inactive_resource``
    * plus ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_start_resource``

* Resources that were started: ``$OCF_RESKEY_CRM_meta_notify_start_resource``
* Resources that were stopped: ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
   
Extra Notifications for Promotable Clones
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. index::
   single: clone; environment variables
   single: promotable; environment variables
   
.. table:: **Extra environment variables supplied for promotable clones**
   :widths: 1 1

   +------------------------------------------------+---------------------------------------------------------------------------------+
   | Variable                                       | Description                                                                     |
   +================================================+=================================================================================+
   | OCF_RESKEY_CRM_meta_notify_promoted_resource   | .. index::                                                                      |
   |                                                |    single: environment variable; OCF_RESKEY_CRM_meta_notify_promoted_resource   |
   |                                                |    single: OCF_RESKEY_CRM_meta_notify_promoted_resource                         |
   |                                                |                                                                                 |
   |                                                | Resources that are running in the promoted role                                 |
   +------------------------------------------------+---------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_unpromoted_resource | .. index::                                                                      |
   |                                                |    single: environment variable; OCF_RESKEY_CRM_meta_notify_unpromoted_resource |
   |                                                |    single: OCF_RESKEY_CRM_meta_notify_unpromoted_resource                       |
   |                                                |                                                                                 |
   |                                                | Resources that are running in the unpromoted role                               |
   +------------------------------------------------+---------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_promote_resource    | .. index::                                                                      |
   |                                                |    single: environment variable; OCF_RESKEY_CRM_meta_notify_promote_resource    |
   |                                                |    single: OCF_RESKEY_CRM_meta_notify_promote_resource                          |
   |                                                |                                                                                 |
   |                                                | Resources to be promoted                                                        |
   +------------------------------------------------+---------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_demote_resource     | .. index::                                                                      |
   |                                                |    single: environment variable; OCF_RESKEY_CRM_meta_notify_demote_resource     |
   |                                                |    single: OCF_RESKEY_CRM_meta_notify_demote_resource                           |
   |                                                |                                                                                 |
   |                                                | Resources to be demoted                                                         |
   +------------------------------------------------+---------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_promote_uname       | .. index::                                                                      |
   |                                                |    single: environment variable; OCF_RESKEY_CRM_meta_notify_promote_uname       |
   |                                                |    single: OCF_RESKEY_CRM_meta_notify_promote_uname                             |
   |                                                |                                                                                 |
   |                                                | Nodes on which resources will be promoted                                       |
   +------------------------------------------------+---------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_demote_uname        | .. index::                                                                      |
   |                                                |    single: environment variable; OCF_RESKEY_CRM_meta_notify_demote_uname        |
   |                                                |    single: OCF_RESKEY_CRM_meta_notify_demote_uname                              |
   |                                                |                                                                                 |
   |                                                | Nodes on which resources will be demoted                                        |
   +------------------------------------------------+---------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_promoted_uname      | .. index::                                                                      |
   |                                                |    single: environment variable; OCF_RESKEY_CRM_meta_notify_promoted_uname      |
   |                                                |    single: OCF_RESKEY_CRM_meta_notify_promoted_uname                            |
   |                                                |                                                                                 |
   |                                                | Nodes on which resources are running in the promoted role                       |
   +------------------------------------------------+---------------------------------------------------------------------------------+
   | OCF_RESKEY_CRM_meta_notify_unpromoted_uname    | .. index::                                                                      |
   |                                                |    single: environment variable; OCF_RESKEY_CRM_meta_notify_unpromoted_uname    |
   |                                                |    single: OCF_RESKEY_CRM_meta_notify_unpromoted_uname                          |
   |                                                |                                                                                 |
   |                                                | Nodes on which resources are running in the unpromoted role                     |
   +------------------------------------------------+---------------------------------------------------------------------------------+
   
Interpretation of Promotable Notification Variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Pre-notification (demote):**

* Active resources: ``$OCF_RESKEY_CRM_meta_notify_active_resource``
* Promoted resources: ``$OCF_RESKEY_CRM_meta_notify_promoted_resource``
* Unpromoted resources: ``$OCF_RESKEY_CRM_meta_notify_unpromoted_resource``
* Inactive resources: ``$OCF_RESKEY_CRM_meta_notify_inactive_resource``
* Resources to be started: ``$OCF_RESKEY_CRM_meta_notify_start_resource``
* Resources to be promoted: ``$OCF_RESKEY_CRM_meta_notify_promote_resource``
* Resources to be demoted: ``$OCF_RESKEY_CRM_meta_notify_demote_resource``
* Resources to be stopped: ``$OCF_RESKEY_CRM_meta_notify_stop_resource``

**Post-notification (demote) / Pre-notification (stop):**

* Active resources: ``$OCF_RESKEY_CRM_meta_notify_active_resource``
* Promoted resources:

    * ``$OCF_RESKEY_CRM_meta_notify_promoted_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_demote_resource`` 

* Unpromoted resources: ``$OCF_RESKEY_CRM_meta_notify_unpromoted_resource``
* Inactive resources: ``$OCF_RESKEY_CRM_meta_notify_inactive_resource``
* Resources to be started: ``$OCF_RESKEY_CRM_meta_notify_start_resource``
* Resources to be promoted: ``$OCF_RESKEY_CRM_meta_notify_promote_resource``
* Resources to be demoted: ``$OCF_RESKEY_CRM_meta_notify_demote_resource``
* Resources to be stopped: ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
* Resources that were demoted: ``$OCF_RESKEY_CRM_meta_notify_demote_resource``
   
**Post-notification (stop) / Pre-notification (start)**
   
* Active resources:

    * ``$OCF_RESKEY_CRM_meta_notify_active_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_stop_resource`` 

* Promoted resources:

    * ``$OCF_RESKEY_CRM_meta_notify_promoted_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_demote_resource`` 

* Unpromoted resources:

    * ``$OCF_RESKEY_CRM_meta_notify_unpromoted_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_stop_resource`` 

* Inactive resources:

    * ``$OCF_RESKEY_CRM_meta_notify_inactive_resource``
    * plus ``$OCF_RESKEY_CRM_meta_notify_stop_resource`` 

* Resources to be started: ``$OCF_RESKEY_CRM_meta_notify_start_resource``
* Resources to be promoted: ``$OCF_RESKEY_CRM_meta_notify_promote_resource``
* Resources to be demoted: ``$OCF_RESKEY_CRM_meta_notify_demote_resource``
* Resources to be stopped: ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
* Resources that were demoted: ``$OCF_RESKEY_CRM_meta_notify_demote_resource``
* Resources that were stopped: ``$OCF_RESKEY_CRM_meta_notify_stop_resource``

**Post-notification (start) / Pre-notification (promote)**

* Active resources:

    * ``$OCF_RESKEY_CRM_meta_notify_active_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
    * plus ``$OCF_RESKEY_CRM_meta_notify_start_resource`` 

* Promoted resources:

    * ``$OCF_RESKEY_CRM_meta_notify_promoted_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_demote_resource`` 

* Unpromoted resources:

    * ``$OCF_RESKEY_CRM_meta_notify_unpromoted_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
    * plus ``$OCF_RESKEY_CRM_meta_notify_start_resource`` 

* Inactive resources:

    * ``$OCF_RESKEY_CRM_meta_notify_inactive_resource``
    * plus ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_start_resource``           

* Resources to be started: ``$OCF_RESKEY_CRM_meta_notify_start_resource``
* Resources to be promoted: ``$OCF_RESKEY_CRM_meta_notify_promote_resource``
* Resources to be demoted: ``$OCF_RESKEY_CRM_meta_notify_demote_resource``
* Resources to be stopped: ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
* Resources that were started: ``$OCF_RESKEY_CRM_meta_notify_start_resource``
* Resources that were demoted: ``$OCF_RESKEY_CRM_meta_notify_demote_resource``
* Resources that were stopped: ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
   
**Post-notification (promote)**
   
* Active resources:

    * ``$OCF_RESKEY_CRM_meta_notify_active_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
    * plus ``$OCF_RESKEY_CRM_meta_notify_start_resource`` 

* Promoted resources:

    * ``$OCF_RESKEY_CRM_meta_notify_promoted_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_demote_resource``
    * plus ``$OCF_RESKEY_CRM_meta_notify_promote_resource``

* Unpromoted resources:

    * ``$OCF_RESKEY_CRM_meta_notify_unpromoted_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
    * plus ``$OCF_RESKEY_CRM_meta_notify_start_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_promote_resource`` 

* Inactive resources:

    * ``$OCF_RESKEY_CRM_meta_notify_inactive_resource``
    * plus ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
    * minus ``$OCF_RESKEY_CRM_meta_notify_start_resource`` 

* Resources to be started: ``$OCF_RESKEY_CRM_meta_notify_start_resource``
* Resources to be promoted: ``$OCF_RESKEY_CRM_meta_notify_promote_resource``
* Resources to be demoted: ``$OCF_RESKEY_CRM_meta_notify_demote_resource``
* Resources to be stopped: ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
* Resources that were started: ``$OCF_RESKEY_CRM_meta_notify_start_resource``
* Resources that were promoted: ``$OCF_RESKEY_CRM_meta_notify_promote_resource``
* Resources that were demoted: ``$OCF_RESKEY_CRM_meta_notify_demote_resource``
* Resources that were stopped: ``$OCF_RESKEY_CRM_meta_notify_stop_resource``
   
Monitoring Promotable Clone Resources
_____________________________________

The usual monitor actions are insufficient to monitor a promotable clone
resource, because Pacemaker needs to verify not only that the resource is
active, but also that its actual role matches its intended one.

Define two monitoring actions: the usual one will cover the unpromoted role,
and an additional one with ``role="Promoted"`` will cover the promoted role.
   
.. topic:: Monitoring both states of a promotable clone resource

   .. code-block:: xml

      <clone id="myPromotableRsc">
         <meta_attributes id="myPromotableRsc-meta">
             <nvpair name="promotable" value="true"/>
         </meta_attributes>
         <primitive id="myRsc" class="ocf" type="myApp" provider="myCorp">
          <operations>
           <op id="public-ip-unpromoted-check" name="monitor" interval="60"/>
           <op id="public-ip-promoted-check" name="monitor" interval="61" role="Promoted"/>
          </operations>
         </primitive>
      </clone> 
   
.. important::

   It is crucial that *every* monitor operation has a different interval!
   Pacemaker currently differentiates between operations
   only by resource and interval; so if (for example) a promotable clone resource
   had the same monitor interval for both roles, Pacemaker would ignore the
   role when checking the status -- which would cause unexpected return
   codes, and therefore unnecessary complications.
   
.. _s-promotion-scores:

Determining Which Instance is Promoted
______________________________________

Pacemaker can choose a promotable clone instance to be promoted in one of two
ways:

* Promotion scores: These are node attributes set via the ``crm_attribute``
  command using the ``--promotion`` option, which generally would be called by
  the resource agent's start action if it supports promotable clones. This tool
  automatically detects both the resource and host, and should be used to set a
  preference for being promoted. Based on this, ``promoted-max``, and
  ``promoted-node-max``, the instance(s) with the highest preference will be
  promoted.

* Constraints: Location constraints can indicate which nodes are most preferred
  to be promoted.
   
.. topic:: Explicitly preferring node1 to be promoted

   .. code-block:: xml

      <rsc_location id="promoted-location" rsc="myPromotableRsc">
          <rule id="promoted-rule" score="100" role="Promoted">
            <expression id="promoted-exp" attribute="#uname" operation="eq" value="node1"/>
          </rule>
      </rsc_location> 

.. index:
   single: bundle resource
   single: resource; bundle
   pair: container; Docker
   pair: container; podman
   pair: container; rkt
   
.. _s-resource-bundle:

Bundles - Containerized Resources
#################################

Pacemaker supports a special syntax for launching a service inside a
`container <https://en.wikipedia.org/wiki/Operating-system-level_virtualization>`_
with any infrastructure it requires: the *bundle*.
   
Pacemaker bundles support `Docker <https://www.docker.com/>`_,
`podman <https://podman.io/>`_ *(since 2.0.1)*, and
`rkt <https://coreos.com/rkt/>`_ container technologies. [#]_
   
.. topic:: A bundle for a containerized web server

   .. code-block:: xml

      <bundle id="httpd-bundle">
         <podman image="pcmk:http" replicas="3"/>
         <network ip-range-start="192.168.122.131"
                  host-netmask="24"
                  host-interface="eth0">
            <port-mapping id="httpd-port" port="80"/>
            </network>
         <storage>
            <storage-mapping id="httpd-syslog"
                             source-dir="/dev/log"
                             target-dir="/dev/log"
                             options="rw"/>
            <storage-mapping id="httpd-root"
                             source-dir="/srv/html"
                             target-dir="/var/www/html"
                             options="rw,Z"/>
            <storage-mapping id="httpd-logs"
                             source-dir-root="/var/log/pacemaker/bundles"
                             target-dir="/etc/httpd/logs"
                             options="rw,Z"/>
         </storage>
         <primitive class="ocf" id="httpd" provider="heartbeat" type="apache"/>
      </bundle>

.. index:
   single: bundle resource
   single: resource; bundle
   
Bundle Prerequisites
____________________
   
Before configuring a bundle in Pacemaker, the user must install the appropriate
container launch technology (Docker, podman, or rkt), and supply a fully
configured container image, on every node allowed to run the bundle.

Pacemaker will create an implicit resource of type **ocf:heartbeat:docker**,
**ocf:heartbeat:podman**, or **ocf:heartbeat:rkt** to manage a bundle's
container. The user must ensure that the appropriate resource agent is
installed on every node allowed to run the bundle.

.. index::
   pair: XML element; bundle
   
Bundle Properties
_________________
   
.. table:: **XML Attributes of a bundle Element**
   :widths: 1 4

   +-------------+-----------------------------------------------+
   | Attribute   | Description                                   |
   +=============+===============================================+
   | id          | .. index::                                    |
   |             |    single: bundle; attribute, id              |
   |             |    single: attribute; id (bundle)             |
   |             |    single: id; bundle attribute               |
   |             |                                               |
   |             | A unique name for the bundle (required)       |
   +-------------+-----------------------------------------------+
   | description | .. index::                                    |
   |             |    single: bundle; attribute, description     |
   |             |    single: attribute; description (bundle)    |
   |             |    single: description; bundle attribute      |
   |             |                                               |
   |             | Arbitrary text (not used by Pacemaker)        |
   +-------------+-----------------------------------------------+
   
A bundle must contain exactly one ``docker``, ``podman``, or ``rkt`` element.

.. index::
   pair: XML element; docker
   pair: XML element; podman
   pair: XML element; rkt
   single: resource; bundle
   
Bundle Container Properties
___________________________
   
.. table:: **XML attributes of a docker, podman, or rkt Element**
   :class: longtable
   :widths: 2 3 4
   
   +-------------------+------------------------------------+---------------------------------------------------+
   | Attribute         | Default                            | Description                                       |
   +===================+====================================+===================================================+
   | image             |                                    | .. index::                                        |
   |                   |                                    |    single: docker; attribute, image               |
   |                   |                                    |    single: attribute; image (docker)              |
   |                   |                                    |    single: image; docker attribute                |
   |                   |                                    |    single: podman; attribute, image               |
   |                   |                                    |    single: attribute; image (podman)              |
   |                   |                                    |    single: image; podman attribute                |
   |                   |                                    |    single: rkt; attribute, image                  |
   |                   |                                    |    single: attribute; image (rkt)                 |
   |                   |                                    |    single: image; rkt attribute                   |
   |                   |                                    |                                                   |
   |                   |                                    | Container image tag (required)                    |
   +-------------------+------------------------------------+---------------------------------------------------+
   | replicas          | Value of ``promoted-max``          | .. index::                                        |
   |                   | if that is positive, else 1        |    single: docker; attribute, replicas            |
   |                   |                                    |    single: attribute; replicas (docker)           |
   |                   |                                    |    single: replicas; docker attribute             |
   |                   |                                    |    single: podman; attribute, replicas            |
   |                   |                                    |    single: attribute; replicas (podman)           |
   |                   |                                    |    single: replicas; podman attribute             |
   |                   |                                    |    single: rkt; attribute, replicas               |
   |                   |                                    |    single: attribute; replicas (rkt)              |
   |                   |                                    |    single: replicas; rkt attribute                |
   |                   |                                    |                                                   |
   |                   |                                    | A positive integer specifying the number of       |
   |                   |                                    | container instances to launch                     |
   +-------------------+------------------------------------+---------------------------------------------------+
   | replicas-per-host | 1                                  | .. index::                                        |
   |                   |                                    |    single: docker; attribute, replicas-per-host   |
   |                   |                                    |    single: attribute; replicas-per-host (docker)  |
   |                   |                                    |    single: replicas-per-host; docker attribute    |
   |                   |                                    |    single: podman; attribute, replicas-per-host   |
   |                   |                                    |    single: attribute; replicas-per-host (podman)  |
   |                   |                                    |    single: replicas-per-host; podman attribute    |
   |                   |                                    |    single: rkt; attribute, replicas-per-host      |
   |                   |                                    |    single: attribute; replicas-per-host (rkt)     |
   |                   |                                    |    single: replicas-per-host; rkt attribute       |
   |                   |                                    |                                                   |
   |                   |                                    | A positive integer specifying the number of       |
   |                   |                                    | container instances allowed to run on a           |
   |                   |                                    | single node                                       |
   +-------------------+------------------------------------+---------------------------------------------------+
   | promoted-max      | 0                                  | .. index::                                        |
   |                   |                                    |    single: docker; attribute, promoted-max        |
   |                   |                                    |    single: attribute; promoted-max (docker)       |
   |                   |                                    |    single: promoted-max; docker attribute         |
   |                   |                                    |    single: podman; attribute, promoted-max        |
   |                   |                                    |    single: attribute; promoted-max (podman)       |
   |                   |                                    |    single: promoted-max; podman attribute         |
   |                   |                                    |    single: rkt; attribute, promoted-max           |
   |                   |                                    |    single: attribute; promoted-max (rkt)          |
   |                   |                                    |    single: promoted-max; rkt attribute            |
   |                   |                                    |                                                   |
   |                   |                                    | A non-negative integer that, if positive,         |
   |                   |                                    | indicates that the containerized service          |
   |                   |                                    | should be treated as a promotable service,        |
   |                   |                                    | with this many replicas allowed to run the        |
   |                   |                                    | service in the promoted role                      |
   +-------------------+------------------------------------+---------------------------------------------------+
   | network           |                                    | .. index::                                        |
   |                   |                                    |    single: docker; attribute, network             |
   |                   |                                    |    single: attribute; network (docker)            |
   |                   |                                    |    single: network; docker attribute              |
   |                   |                                    |    single: podman; attribute, network             |
   |                   |                                    |    single: attribute; network (podman)            |
   |                   |                                    |    single: network; podman attribute              |
   |                   |                                    |    single: rkt; attribute, network                |
   |                   |                                    |    single: attribute; network (rkt)               |
   |                   |                                    |    single: network; rkt attribute                 |
   |                   |                                    |                                                   |
   |                   |                                    | If specified, this will be passed to the          |
   |                   |                                    | ``docker run``, ``podman run``, or                |
   |                   |                                    | ``rkt run`` command as the network setting        |
   |                   |                                    | for the container.                                |
   +-------------------+------------------------------------+---------------------------------------------------+
   | run-command       | ``/usr/sbin/pacemaker-remoted`` if | .. index::                                        |
   |                   | bundle contains a **primitive**,   |    single: docker; attribute, run-command         |
   |                   | otherwise none                     |    single: attribute; run-command (docker)        |
   |                   |                                    |    single: run-command; docker attribute          |
   |                   |                                    |    single: podman; attribute, run-command         |
   |                   |                                    |    single: attribute; run-command (podman)        |
   |                   |                                    |    single: run-command; podman attribute          |
   |                   |                                    |    single: rkt; attribute, run-command            |
   |                   |                                    |    single: attribute; run-command (rkt)           |
   |                   |                                    |    single: run-command; rkt attribute             |
   |                   |                                    |                                                   |
   |                   |                                    | This command will be run inside the container     |
   |                   |                                    | when launching it ("PID 1"). If the bundle        |
   |                   |                                    | contains a **primitive**, this command *must*     |
   |                   |                                    | start ``pacemaker-remoted`` (but could, for       |
   |                   |                                    | example, be a script that does other stuff, too). |
   +-------------------+------------------------------------+---------------------------------------------------+
   | options           |                                    | .. index::                                        |
   |                   |                                    |    single: docker; attribute, options             |
   |                   |                                    |    single: attribute; options (docker)            |
   |                   |                                    |    single: options; docker attribute              |
   |                   |                                    |    single: podman; attribute, options             |
   |                   |                                    |    single: attribute; options (podman)            |
   |                   |                                    |    single: options; podman attribute              |
   |                   |                                    |    single: rkt; attribute, options                |
   |                   |                                    |    single: attribute; options (rkt)               |
   |                   |                                    |    single: options; rkt attribute                 |
   |                   |                                    |                                                   |
   |                   |                                    | Extra command-line options to pass to the         |
   |                   |                                    | ``docker run``, ``podman run``, or ``rkt run``    |
   |                   |                                    | command                                           |
   +-------------------+------------------------------------+---------------------------------------------------+
   
.. note::

   Considerations when using cluster configurations or container images from
   Pacemaker 1.1:
   
   * If the container image has a pre-2.0.0 version of Pacemaker, set ``run-command``
     to ``/usr/sbin/pacemaker_remoted`` (note the underbar instead of dash).
   
   * ``masters`` is accepted as an alias for ``promoted-max``, but is deprecated since
     2.0.0, and support for it will be removed in a future version.

Bundle Network Properties
_________________________
   
A bundle may optionally contain one ``<network>`` element.

.. index::
   pair: XML element; network
   single: resource; bundle
   single: bundle; networking
   
.. table:: **XML attributes of a network Element**
   :widths: 2 1 5
   
   +----------------+---------+------------------------------------------------------------+
   | Attribute      | Default | Description                                                |
   +================+=========+============================================================+
   | add-host       | TRUE    | .. index::                                                 |
   |                |         |    single: network; attribute, add-host                    |
   |                |         |    single: attribute; add-host (network)                   |
   |                |         |    single: add-host; network attribute                     |
   |                |         |                                                            |
   |                |         | If TRUE, and ``ip-range-start`` is used, Pacemaker will    |
   |                |         | automatically ensure that ``/etc/hosts`` inside the        |
   |                |         | containers has entries for each                            |
   |                |         | :ref:`replica name <s-resource-bundle-note-replica-names>` |
   |                |         | and its assigned IP.                                       |
   +----------------+---------+------------------------------------------------------------+
   | ip-range-start |         | .. index::                                                 |
   |                |         |    single: network; attribute, ip-range-start              |
   |                |         |    single: attribute; ip-range-start (network)             |
   |                |         |    single: ip-range-start; network attribute               |
   |                |         |                                                            |
   |                |         | If specified, Pacemaker will create an implicit            |
   |                |         | ``ocf:heartbeat:IPaddr2`` resource for each container      |
   |                |         | instance, starting with this IP address, using up to       |
   |                |         | ``replicas`` sequential addresses. These addresses can be  |
   |                |         | used from the host's network to reach the service inside   |
   |                |         | the container, though it is not visible within the         |
   |                |         | container itself. Only IPv4 addresses are currently        |
   |                |         | supported.                                                 |
   +----------------+---------+------------------------------------------------------------+
   | host-netmask   | 32      | .. index::                                                 |
   |                |         |    single: network; attribute; host-netmask                |
   |                |         |    single: attribute; host-netmask (network)               |
   |                |         |    single: host-netmask; network attribute                 |
   |                |         |                                                            |
   |                |         | If ``ip-range-start`` is specified, the IP addresses       |
   |                |         | are created with this CIDR netmask (as a number of bits).  |
   +----------------+---------+------------------------------------------------------------+
   | host-interface |         | .. index::                                                 |
   |                |         |    single: network; attribute; host-interface              |
   |                |         |    single: attribute; host-interface (network)             |
   |                |         |    single: host-interface; network attribute               |
   |                |         |                                                            |
   |                |         | If ``ip-range-start`` is specified, the IP addresses are   |
   |                |         | created on this host interface (by default, it will be     |
   |                |         | determined from the IP address).                           |
   +----------------+---------+------------------------------------------------------------+
   | control-port   | 3121    | .. index::                                                 |
   |                |         |    single: network; attribute; control-port                |
   |                |         |    single: attribute; control-port (network)               |
   |                |         |    single: control-port; network attribute                 |
   |                |         |                                                            |
   |                |         | If the bundle contains a ``primitive``, the cluster will   |
   |                |         | use this integer TCP port for communication with           |
   |                |         | Pacemaker Remote inside the container. Changing this is    |
   |                |         | useful when the container is unable to listen on the       |
   |                |         | default port, for example, when the container uses the     |
   |                |         | host's network rather than ``ip-range-start`` (in which    |
   |                |         | case ``replicas-per-host`` must be 1), or when the bundle  |
   |                |         | may run on a Pacemaker Remote node that is already         |
   |                |         | listening on the default port. Any ``PCMK_remote_port``    |
   |                |         | environment variable set on the host or in the container   |
   |                |         | is ignored for bundle connections.                         |
   +----------------+---------+------------------------------------------------------------+
   
.. _s-resource-bundle-note-replica-names:

.. note::

   Replicas are named by the bundle id plus a dash and an integer counter starting
   with zero. For example, if a bundle named **httpd-bundle** has **replicas=2**, its
   containers will be named **httpd-bundle-0** and **httpd-bundle-1**.

.. index::
   pair: XML element; port-mapping
   
Additionally, a ``network`` element may optionally contain one or more
``port-mapping`` elements.
   
.. table:: **Attributes of a port-mapping Element**
   :widths: 2 1 5
   
   +---------------+-------------------+------------------------------------------------------+
   | Attribute     | Default           | Description                                          |
   +===============+===================+======================================================+
   | id            |                   | .. index::                                           |
   |               |                   |    single: port-mapping; attribute, id               |
   |               |                   |    single: attribute; id (port-mapping)              |
   |               |                   |    single: id; port-mapping attribute                |
   |               |                   |                                                      |
   |               |                   | A unique name for the port mapping (required)        |
   +---------------+-------------------+------------------------------------------------------+
   | port          |                   | .. index::                                           |
   |               |                   |    single: port-mapping; attribute, port             |
   |               |                   |    single: attribute; port (port-mapping)            |
   |               |                   |    single: port; port-mapping attribute              |
   |               |                   |                                                      |
   |               |                   | If this is specified, connections to this TCP port   |
   |               |                   | number on the host network (on the container's       |
   |               |                   | assigned IP address, if ``ip-range-start`` is        |
   |               |                   | specified) will be forwarded to the container        |
   |               |                   | network. Exactly one of ``port`` or ``range``        |
   |               |                   | must be specified in a ``port-mapping``.             |
   +---------------+-------------------+------------------------------------------------------+
   | internal-port | value of ``port`` | .. index::                                           |
   |               |                   |    single: port-mapping; attribute, internal-port    |
   |               |                   |    single: attribute; internal-port (port-mapping)   |
   |               |                   |    single: internal-port; port-mapping attribute     |
   |               |                   |                                                      |
   |               |                   | If ``port`` and this are specified, connections      |
   |               |                   | to ``port`` on the host's network will be            |
   |               |                   | forwarded to this port on the container network.     |
   +---------------+-------------------+------------------------------------------------------+
   | range         |                   | .. index::                                           |
   |               |                   |    single: port-mapping; attribute, range            |
   |               |                   |    single: attribute; range (port-mapping)           |
   |               |                   |    single: range; port-mapping attribute             |
   |               |                   |                                                      |
   |               |                   | If this is specified, connections to these TCP       |
   |               |                   | port numbers (expressed as *first_port*-*last_port*) |
   |               |                   | on the host network (on the container's assigned IP  |
   |               |                   | address, if ``ip-range-start`` is specified) will    |
   |               |                   | be forwarded to the same ports in the container      |
   |               |                   | network. Exactly one of ``port`` or ``range``        |
   |               |                   | must be specified in a ``port-mapping``.             |
   +---------------+-------------------+------------------------------------------------------+

.. note::

   If the bundle contains a ``primitive``, Pacemaker will automatically map the
   ``control-port``, so it is not necessary to specify that port in a
   ``port-mapping``.

.. index:
   pair: XML element; storage
   pair: XML element; storage-mapping
   single: resource; bundle
   
.. _s-bundle-storage:

Bundle Storage Properties
_________________________
   
A bundle may optionally contain one ``storage`` element. A ``storage`` element
has no properties of its own, but may contain one or more ``storage-mapping``
elements.
   
.. table:: **Attributes of a storage-mapping Element**
   :widths: 2 1 5
   
   +-----------------+---------+-------------------------------------------------------------+
   | Attribute       | Default | Description                                                 |
   +=================+=========+=============================================================+
   | id              |         | .. index::                                                  |
   |                 |         |    single: storage-mapping; attribute, id                   |
   |                 |         |    single: attribute; id (storage-mapping)                  |
   |                 |         |    single: id; storage-mapping attribute                    |
   |                 |         |                                                             |
   |                 |         | A unique name for the storage mapping (required)            |
   +-----------------+---------+-------------------------------------------------------------+
   | source-dir      |         | .. index::                                                  |
   |                 |         |    single: storage-mapping; attribute, source-dir           |
   |                 |         |    single: attribute; source-dir (storage-mapping)          |
   |                 |         |    single: source-dir; storage-mapping attribute            |
   |                 |         |                                                             |
   |                 |         | The absolute path on the host's filesystem that will be     |
   |                 |         | mapped into the container. Exactly one of ``source-dir``    |
   |                 |         | and ``source-dir-root`` must be specified in a              |
   |                 |         | ``storage-mapping``.                                        |
   +-----------------+---------+-------------------------------------------------------------+
   | source-dir-root |         | .. index::                                                  |
   |                 |         |    single: storage-mapping; attribute, source-dir-root      |
   |                 |         |    single: attribute; source-dir-root (storage-mapping)     |
   |                 |         |    single: source-dir-root; storage-mapping attribute       |
   |                 |         |                                                             |
   |                 |         | The start of a path on the host's filesystem that will      |
   |                 |         | be mapped into the container, using a different             |
   |                 |         | subdirectory on the host for each container instance.       |
   |                 |         | The subdirectory will be named the same as the              |
   |                 |         | :ref:`replica name <s-resource-bundle-note-replica-names>`. |
   |                 |         | Exactly one of ``source-dir`` and ``source-dir-root``       |
   |                 |         | must be specified in a ``storage-mapping``.                 |
   +-----------------+---------+-------------------------------------------------------------+
   | target-dir      |         | .. index::                                                  |
   |                 |         |    single: storage-mapping; attribute, target-dir           |
   |                 |         |    single: attribute; target-dir (storage-mapping)          |
   |                 |         |    single: target-dir; storage-mapping attribute            |
   |                 |         |                                                             |
   |                 |         | The path name within the container where the host           |
   |                 |         | storage will be mapped (required)                           |
   +-----------------+---------+-------------------------------------------------------------+
   | options         |         | .. index::                                                  |
   |                 |         |    single: storage-mapping; attribute, options              |
   |                 |         |    single: attribute; options (storage-mapping)             |
   |                 |         |    single: options; storage-mapping attribute               |
   |                 |         |                                                             |
   |                 |         | A comma-separated list of file system mount                 |
   |                 |         | options to use when mapping the storage                     |
   +-----------------+---------+-------------------------------------------------------------+
   
.. note::

   Pacemaker does not define the behavior if the source directory does not already
   exist on the host. However, it is expected that the container technology and/or
   its resource agent will create the source directory in that case.
   
.. note::

   If the bundle contains a ``primitive``,
   Pacemaker will automatically map the equivalent of
   ``source-dir=/etc/pacemaker/authkey target-dir=/etc/pacemaker/authkey``
   and ``source-dir-root=/var/log/pacemaker/bundles target-dir=/var/log`` into the
   container, so it is not necessary to specify those paths in a
   ``storage-mapping``.
   
.. important::

   The ``PCMK_authkey_location`` environment variable must not be set to anything
   other than the default of ``/etc/pacemaker/authkey`` on any node in the cluster.
   
.. important::

   If SELinux is used in enforcing mode on the host, you must ensure the container
   is allowed to use any storage you mount into it. For Docker and podman bundles,
   adding "Z" to the mount options will create a container-specific label for the
   mount that allows the container access.

.. index::
   single: resource; bundle
   
Bundle Primitive
________________
   
A bundle may optionally contain one :ref:`primitive <primitive-resource>`
resource. The primitive may have operations, instance attributes, and
meta-attributes defined, as usual.

If a bundle contains a primitive resource, the container image must include
the Pacemaker Remote daemon, and at least one of ``ip-range-start`` or
``control-port`` must be configured in the bundle. Pacemaker will create an
implicit **ocf:pacemaker:remote** resource for the connection, launch
Pacemaker Remote within the container, and monitor and manage the primitive
resource via Pacemaker Remote.

If the bundle has more than one container instance (replica), the primitive
resource will function as an implicit :ref:`clone <s-resource-clone>` -- a
:ref:`promotable clone <s-resource-promotable>` if the bundle has ``promoted-max``
greater than zero.
    
.. note::

   If you want to pass environment variables to a bundle's Pacemaker Remote
   connection or primitive, you have two options:
   
   * Environment variables whose value is the same regardless of the underlying host
     may be set using the container element's ``options`` attribute.
   * If you want variables to have host-specific values, you can use the
     :ref:`storage-mapping <s-bundle-storage>` element to map a file on the host as
     ``/etc/pacemaker/pcmk-init.env`` in the container *(since 2.0.3)*.
     Pacemaker Remote will parse this file as a shell-like format, with
     variables set as NAME=VALUE, ignoring blank lines and comments starting
     with "#".
   
.. important::

   When a bundle has a ``primitive``, Pacemaker on all cluster nodes must be able to
   contact Pacemaker Remote inside the bundle's containers.
   
   * The containers must have an accessible network (for example, ``network`` should
     not be set to "none" with a ``primitive``).
   * The default, using a distinct network space inside the container, works in
     combination with ``ip-range-start``. Any firewall must allow access from all
     cluster nodes to the ``control-port`` on the container IPs.
   * If the container shares the host's network space (for example, by setting
     ``network`` to "host"), a unique ``control-port`` should be specified for each
     bundle. Any firewall must allow access from all cluster nodes to the
     ``control-port`` on all cluster and remote node IPs.
   
.. index::
   single: resource; bundle

.. _s-bundle-attributes:

Bundle Node Attributes
______________________
   
If the bundle has a ``primitive``, the primitive's resource agent may want to set
node attributes such as :ref:`promotion scores <s-promotion-scores>`. However, with
containers, it is not apparent which node should get the attribute.

If the container uses shared storage that is the same no matter which node the
container is hosted on, then it is appropriate to use the promotion score on the
bundle node itself.

On the other hand, if the container uses storage exported from the underlying host,
then it may be more appropriate to use the promotion score on the underlying host.

Since this depends on the particular situation, the
``container-attribute-target`` resource meta-attribute allows the user to specify
which approach to use. If it is set to ``host``, then user-defined node attributes
will be checked on the underlying host. If it is anything else, the local node
(in this case the bundle node) is used as usual.

This only applies to user-defined attributes; the cluster will always check the
local node for cluster-defined attributes such as ``#uname``.

If ``container-attribute-target`` is ``host``, the cluster will pass additional
environment variables to the primitive's resource agent that allow it to set
node attributes appropriately: ``CRM_meta_container_attribute_target`` (identical
to the meta-attribute value) and ``CRM_meta_physical_host`` (the name of the
underlying host).
   
.. note::

   When called by a resource agent, the ``attrd_updater`` and ``crm_attribute``
   commands will automatically check those environment variables and set
   attributes appropriately.
   
.. index::
   single: resource; bundle

Bundle Meta-Attributes
______________________
   
Any meta-attribute set on a bundle will be inherited by the bundle's
primitive and any resources implicitly created by Pacemaker for the bundle.

This includes options such as ``priority``, ``target-role``, and ``is-managed``. See
:ref:`resource_options` for more information.
   
Limitations of Bundles
______________________
   
Restarting pacemaker while a bundle is unmanaged or the cluster is in
maintenance mode may cause the bundle to fail.

Bundles may not be explicitly cloned or included in groups. This includes the
bundle's primitive and any resources implicitly created by Pacemaker for the
bundle. (If ``replicas`` is greater than 1, the bundle will behave like a clone
implicitly.)

Bundles do not have instance attributes, utilization attributes, or operations,
though a bundle's primitive may have them.

A bundle with a primitive can run on a Pacemaker Remote node only if the bundle
uses a distinct ``control-port``.

.. [#] Of course, the service must support running multiple instances.

.. [#] Docker is a trademark of Docker, Inc. No endorsement by or association with
   Docker, Inc. is implied.
