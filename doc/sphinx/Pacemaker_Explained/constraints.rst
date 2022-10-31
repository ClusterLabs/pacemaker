.. index::
   single: constraint
   single: resource; constraint

.. _constraints:

Resource Constraints
--------------------

.. index::
   single: resource; score
   single: node; score

Scores
######

Scores of all kinds are integral to how the cluster works.
Practically everything from moving a resource to deciding which
resource to stop in a degraded cluster is achieved by manipulating
scores in some way.

Scores are calculated per resource and node. Any node with a
negative score for a resource can't run that resource. The cluster
places a resource on the node with the highest score for it.

Infinity Math
_____________

Pacemaker implements **INFINITY** (or equivalently, **+INFINITY**) internally as a
score of 1,000,000. Addition and subtraction with it follow these three basic
rules:

* Any value + **INFINITY** = **INFINITY**

* Any value - **INFINITY** = -**INFINITY**

* **INFINITY** - **INFINITY** = **-INFINITY**

.. note::

   What if you want to use a score higher than 1,000,000? Typically this possibility
   arises when someone wants to base the score on some external metric that might
   go above 1,000,000.

   The short answer is you can't.

   The long answer is it is sometimes possible work around this limitation
   creatively. You may be able to set the score to some computed value based on
   the external metric rather than use the metric directly. For nodes, you can
   store the metric as a node attribute, and query the attribute when computing
   the score (possibly as part of a custom resource agent).

.. _location-constraint:

.. index::
   single: location constraint
   single: constraint; location

Deciding Which Nodes a Resource Can Run On
##########################################

*Location constraints* tell the cluster which nodes a resource can run on.

There are two alternative strategies. One way is to say that, by default,
resources can run anywhere, and then the location constraints specify nodes
that are not allowed (an *opt-out* cluster). The other way is to start with
nothing able to run anywhere, and use location constraints to selectively
enable allowed nodes (an *opt-in* cluster).

Whether you should choose opt-in or opt-out depends on your
personal preference and the make-up of your cluster.  If most of your
resources can run on most of the nodes, then an opt-out arrangement is
likely to result in a simpler configuration.  On the other-hand, if
most resources can only run on a small subset of nodes, an opt-in
configuration might be simpler.

.. index::
   pair: XML element; rsc_location
   single: constraint; rsc_location

Location Properties
___________________

.. table:: **Attributes of a rsc_location Element**
   :class: longtable
   :widths: 1 1 4

   +--------------------+---------+----------------------------------------------------------------------------------------------+
   | Attribute          | Default | Description                                                                                  |
   +====================+=========+==============================================================================================+
   | id                 |         | .. index::                                                                                   |
   |                    |         |    single: rsc_location; attribute, id                                                       |
   |                    |         |    single: attribute; id (rsc_location)                                                      |
   |                    |         |    single: id; rsc_location attribute                                                        |
   |                    |         |                                                                                              |
   |                    |         | A unique name for the constraint (required)                                                  |
   +--------------------+---------+----------------------------------------------------------------------------------------------+
   | rsc                |         | .. index::                                                                                   |
   |                    |         |    single: rsc_location; attribute, rsc                                                      |
   |                    |         |    single: attribute; rsc (rsc_location)                                                     |
   |                    |         |    single: rsc; rsc_location attribute                                                       |
   |                    |         |                                                                                              |
   |                    |         | The name of the resource to which this constraint                                            |
   |                    |         | applies. A location constraint must either have a                                            |
   |                    |         | ``rsc``, have a ``rsc-pattern``, or contain at                                               |
   |                    |         | least one resource set.                                                                      |
   +--------------------+---------+----------------------------------------------------------------------------------------------+
   | rsc-pattern        |         | .. index::                                                                                   |
   |                    |         |    single: rsc_location; attribute, rsc-pattern                                              |
   |                    |         |    single: attribute; rsc-pattern (rsc_location)                                             |
   |                    |         |    single: rsc-pattern; rsc_location attribute                                               |
   |                    |         |                                                                                              |
   |                    |         | A pattern matching the names of resources to which                                           |
   |                    |         | this constraint applies.  The syntax is the same as                                          |
   |                    |         | `POSIX <http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap09.html#tag_09_04>`_ |
   |                    |         | extended regular expressions, with the addition of an                                        |
   |                    |         | initial *!* indicating that resources *not* matching                                         |
   |                    |         | the pattern are selected. If the regular expression                                          |
   |                    |         | contains submatches, and the constraint is governed by                                       |
   |                    |         | a :ref:`rule <rules>`, the submatches can be                                                 |
   |                    |         | referenced as **%1** through **%9** in the rule's                                            |
   |                    |         | ``score-attribute`` or a rule expression's ``attribute``.                                    |
   |                    |         | A location constraint must either have a ``rsc``, have a                                     |
   |                    |         | ``rsc-pattern``, or contain at least one resource set.                                       |
   +--------------------+---------+----------------------------------------------------------------------------------------------+
   | node               |         | .. index::                                                                                   |
   |                    |         |    single: rsc_location; attribute, node                                                     |
   |                    |         |    single: attribute; node (rsc_location)                                                    |
   |                    |         |    single: node; rsc_location attribute                                                      |
   |                    |         |                                                                                              |
   |                    |         | The name of the node to which this constraint applies.                                       |
   |                    |         | A location constraint must either have a ``node`` and                                        |
   |                    |         | ``score``, or contain at least one rule.                                                     |
   +--------------------+---------+----------------------------------------------------------------------------------------------+
   | score              |         | .. index::                                                                                   |
   |                    |         |    single: rsc_location; attribute, score                                                    |
   |                    |         |    single: attribute; score (rsc_location)                                                   |
   |                    |         |    single: score; rsc_location attribute                                                     |
   |                    |         |                                                                                              |
   |                    |         | Positive values indicate a preference for running the                                        |
   |                    |         | affected resource(s) on ``node`` -- the higher the value,                                    |
   |                    |         | the stronger the preference. Negative values indicate                                        |
   |                    |         | the resource(s) should avoid this node (a value of                                           |
   |                    |         | **-INFINITY** changes "should" to "must"). A location                                        |
   |                    |         | constraint must either have a ``node`` and ``score``,                                        |
   |                    |         | or contain at least one rule.                                                                |
   +--------------------+---------+----------------------------------------------------------------------------------------------+
   | resource-discovery | always  | .. index::                                                                                   |
   |                    |         |    single: rsc_location; attribute, resource-discovery                                       |
   |                    |         |    single: attribute; resource-discovery (rsc_location)                                      |
   |                    |         |    single: resource-discovery; rsc_location attribute                                        |
   |                    |         |                                                                                              |
   |                    |         | Whether Pacemaker should perform resource discovery                                          |
   |                    |         | (that is, check whether the resource is already running)                                     |
   |                    |         | for this resource on this node. This should normally be                                      |
   |                    |         | left as the default, so that rogue instances of a                                            |
   |                    |         | service can be stopped when they are running where they                                      |
   |                    |         | are not supposed to be. However, there are two                                               |
   |                    |         | situations where disabling resource discovery is a good                                      |
   |                    |         | idea: when a service is not installed on a node,                                             |
   |                    |         | discovery might return an error (properly written OCF                                        |
   |                    |         | agents will not, so this is usually only seen with other                                     |
   |                    |         | agent types); and when Pacemaker Remote is used to scale                                     |
   |                    |         | a cluster to hundreds of nodes, limiting resource                                            |
   |                    |         | discovery to allowed nodes can significantly boost                                           |
   |                    |         | performance.                                                                                 |
   |                    |         |                                                                                              |
   |                    |         | * ``always:`` Always perform resource discovery for                                          |
   |                    |         |   the specified resource on this node.                                                       |
   |                    |         |                                                                                              |
   |                    |         | * ``never:`` Never perform resource discovery for the                                        |
   |                    |         |   specified resource on this node.  This option should                                       |
   |                    |         |   generally be used with a -INFINITY score, although                                         |
   |                    |         |   that is not strictly required.                                                             |
   |                    |         |                                                                                              |
   |                    |         | * ``exclusive:`` Perform resource discovery for the                                          |
   |                    |         |   specified resource only on this node (and other nodes                                      |
   |                    |         |   similarly marked as ``exclusive``). Multiple location                                      |
   |                    |         |   constraints using ``exclusive`` discovery for the                                          |
   |                    |         |   same resource across different nodes creates a subset                                      |
   |                    |         |   of nodes resource-discovery is exclusive to.  If a                                         |
   |                    |         |   resource is marked for ``exclusive`` discovery on one                                      |
   |                    |         |   or more nodes, that resource is only allowed to be                                         |
   |                    |         |   placed within that subset of nodes.                                                        |
   +--------------------+---------+----------------------------------------------------------------------------------------------+

.. warning::

   Setting ``resource-discovery`` to ``never`` or ``exclusive`` removes Pacemaker's
   ability to detect and stop unwanted instances of a service running
   where it's not supposed to be. It is up to the system administrator (you!)
   to make sure that the service can *never* be active on nodes without
   ``resource-discovery`` (such as by leaving the relevant software uninstalled).

.. index::
  single: Asymmetrical Clusters
  single: Opt-In Clusters

Asymmetrical "Opt-In" Clusters
______________________________

To create an opt-in cluster, start by preventing resources from running anywhere
by default:

.. code-block:: none

   # crm_attribute --name symmetric-cluster --update false

Then start enabling nodes.  The following fragment says that the web
server prefers **sles-1**, the database prefers **sles-2** and both can
fail over to **sles-3** if their most preferred node fails.

.. topic:: Opt-in location constraints for two resources

   .. code-block:: xml

      <constraints>
          <rsc_location id="loc-1" rsc="Webserver" node="sles-1" score="200"/>
          <rsc_location id="loc-2" rsc="Webserver" node="sles-3" score="0"/>
          <rsc_location id="loc-3" rsc="Database" node="sles-2" score="200"/>
          <rsc_location id="loc-4" rsc="Database" node="sles-3" score="0"/>
      </constraints>

.. index::
  single: Symmetrical Clusters
  single: Opt-Out Clusters

Symmetrical "Opt-Out" Clusters
______________________________

To create an opt-out cluster, start by allowing resources to run
anywhere by default:

.. code-block:: none

   # crm_attribute --name symmetric-cluster --update true

Then start disabling nodes.  The following fragment is the equivalent
of the above opt-in configuration.

.. topic:: Opt-out location constraints for two resources

   .. code-block:: xml

      <constraints>
          <rsc_location id="loc-1" rsc="Webserver" node="sles-1" score="200"/>
          <rsc_location id="loc-2-do-not-run" rsc="Webserver" node="sles-2" score="-INFINITY"/>
          <rsc_location id="loc-3-do-not-run" rsc="Database" node="sles-1" score="-INFINITY"/>
          <rsc_location id="loc-4" rsc="Database" node="sles-2" score="200"/>
      </constraints>

.. _node-score-equal:

What if Two Nodes Have the Same Score
_____________________________________

If two nodes have the same score, then the cluster will choose one.
This choice may seem random and may not be what was intended, however
the cluster was not given enough information to know any better.

.. topic:: Constraints where a resource prefers two nodes equally

   .. code-block:: xml

      <constraints>
          <rsc_location id="loc-1" rsc="Webserver" node="sles-1" score="INFINITY"/>
          <rsc_location id="loc-2" rsc="Webserver" node="sles-2" score="INFINITY"/>
          <rsc_location id="loc-3" rsc="Database" node="sles-1" score="500"/>
          <rsc_location id="loc-4" rsc="Database" node="sles-2" score="300"/>
          <rsc_location id="loc-5" rsc="Database" node="sles-2" score="200"/>
      </constraints>

In the example above, assuming no other constraints and an inactive
cluster, **Webserver** would probably be placed on **sles-1** and **Database** on
**sles-2**.  It would likely have placed **Webserver** based on the node's
uname and **Database** based on the desire to spread the resource load
evenly across the cluster.  However other factors can also be involved
in more complex configurations.

.. index::
   single: constraint; ordering
   single: resource; start order

.. _s-resource-ordering:

Specifying the Order in which Resources Should Start/Stop
#########################################################

*Ordering constraints* tell the cluster the order in which certain
resource actions should occur.

.. important::

   Ordering constraints affect *only* the ordering of resource actions;
   they do *not* require that the resources be placed on the
   same node. If you want resources to be started on the same node
   *and* in a specific order, you need both an ordering constraint *and*
   a colocation constraint (see :ref:`s-resource-colocation`), or
   alternatively, a group (see :ref:`group-resources`).

.. index::
   pair: XML element; rsc_order
   pair: constraint; rsc_order

Ordering Properties
___________________

.. table:: **Attributes of a rsc_order Element**
   :class: longtable
   :widths: 1 2 4

   +--------------+----------------------------+-------------------------------------------------------------------+
   | Field        | Default                    | Description                                                       |
   +==============+============================+===================================================================+
   | id           |                            | .. index::                                                        |
   |              |                            |    single: rsc_order; attribute, id                               |
   |              |                            |    single: attribute; id (rsc_order)                              |
   |              |                            |    single: id; rsc_order attribute                                |
   |              |                            |                                                                   |
   |              |                            | A unique name for the constraint                                  |
   +--------------+----------------------------+-------------------------------------------------------------------+
   | first        |                            | .. index::                                                        |
   |              |                            |    single: rsc_order; attribute, first                            |
   |              |                            |    single: attribute; first (rsc_order)                           |
   |              |                            |    single: first; rsc_order attribute                             |
   |              |                            |                                                                   |
   |              |                            | Name of the resource that the ``then`` resource                   |
   |              |                            | depends on                                                        |
   +--------------+----------------------------+-------------------------------------------------------------------+
   | then         |                            | .. index::                                                        |
   |              |                            |    single: rsc_order; attribute, then                             |
   |              |                            |    single: attribute; then (rsc_order)                            |
   |              |                            |    single: then; rsc_order attribute                              |
   |              |                            |                                                                   |
   |              |                            | Name of the dependent resource                                    |
   +--------------+----------------------------+-------------------------------------------------------------------+
   | first-action | start                      | .. index::                                                        |
   |              |                            |    single: rsc_order; attribute, first-action                     |
   |              |                            |    single: attribute; first-action (rsc_order)                    |
   |              |                            |    single: first-action; rsc_order attribute                      |
   |              |                            |                                                                   |
   |              |                            | The action that the ``first`` resource must complete              |
   |              |                            | before ``then-action`` can be initiated for the ``then``          |
   |              |                            | resource.  Allowed values: ``start``, ``stop``,                   |
   |              |                            | ``promote``, ``demote``.                                          |
   +--------------+----------------------------+-------------------------------------------------------------------+
   | then-action  | value of ``first-action``  | .. index::                                                        |
   |              |                            |    single: rsc_order; attribute, then-action                      |
   |              |                            |    single: attribute; then-action (rsc_order)                     |
   |              |                            |    single: first-action; rsc_order attribute                      |
   |              |                            |                                                                   |
   |              |                            | The action that the ``then`` resource can execute only            |
   |              |                            | after the ``first-action`` on the ``first`` resource has          |
   |              |                            | completed.  Allowed values: ``start``, ``stop``,                  |
   |              |                            | ``promote``, ``demote``.                                          |
   +--------------+----------------------------+-------------------------------------------------------------------+
   | kind         | Mandatory                  | .. index::                                                        |
   |              |                            |    single: rsc_order; attribute, kind                             |
   |              |                            |    single: attribute; kind (rsc_order)                            |
   |              |                            |    single: kind; rsc_order attribute                              |
   |              |                            |                                                                   |
   |              |                            | How to enforce the constraint. Allowed values:                    |
   |              |                            |                                                                   |
   |              |                            | * ``Mandatory:`` ``then-action`` will never be initiated          |
   |              |                            |   for the ``then`` resource unless and until ``first-action``     |
   |              |                            |   successfully completes for the ``first`` resource.              |
   |              |                            |                                                                   |
   |              |                            | * ``Optional:`` The constraint applies only if both specified     |
   |              |                            |   resource actions are scheduled in the same transition           |
   |              |                            |   (that is, in response to the same cluster state). This          |
   |              |                            |   means that ``then-action`` is allowed on the ``then``           |
   |              |                            |   resource regardless of the state of the ``first`` resource,     |
   |              |                            |   but if both actions happen to be scheduled at the same time,    |
   |              |                            |   they will be ordered.                                           |
   |              |                            |                                                                   |
   |              |                            | * ``Serialize:`` Ensure that the specified actions are never      |
   |              |                            |   performed concurrently for the specified resources.             |
   |              |                            |   ``First-action`` and ``then-action`` can be executed in either  |
   |              |                            |   order, but one must complete before the other can be initiated. |
   |              |                            |   An example use case is when resource start-up puts a high load  |
   |              |                            |   on the host.                                                    |
   +--------------+----------------------------+-------------------------------------------------------------------+
   | symmetrical  | TRUE for ``Mandatory`` and | .. index::                                                        |
   |              | ``Optional`` kinds. FALSE  |    single: rsc_order; attribute, symmetrical                      |
   |              | for ``Serialize`` kind.    |    single: attribute; symmetrical (rsc)order)                     |
   |              |                            |    single: symmetrical; rsc_order attribute                       |
   |              |                            |                                                                   |
   |              |                            | If true, the reverse of the constraint applies for the            |
   |              |                            | opposite action (for example, if B starts after A starts,         |
   |              |                            | then B stops before A stops).  ``Serialize`` orders cannot        |
   |              |                            | be symmetrical.                                                   |
   +--------------+----------------------------+-------------------------------------------------------------------+

``Promote`` and ``demote`` apply to :ref:`promotable <s-resource-promotable>`
clone resources.

Optional and mandatory ordering
_______________________________

Here is an example of ordering constraints where **Database** *must* start before
**Webserver**, and **IP** *should* start before **Webserver** if they both need to be
started:

.. topic:: Optional and mandatory ordering constraints

   .. code-block:: xml

      <constraints>
          <rsc_order id="order-1" first="IP" then="Webserver" kind="Optional"/>
          <rsc_order id="order-2" first="Database" then="Webserver" kind="Mandatory" />
      </constraints>

Because the above example lets ``symmetrical`` default to TRUE, **Webserver**
must be stopped before **Database** can be stopped, and **Webserver** should be
stopped before **IP** if they both need to be stopped.

.. index::
   single: colocation
   single: constraint; colocation
   single: resource; location relative to other resources

.. _s-resource-colocation:

Placing Resources Relative to other Resources
#############################################

*Colocation constraints* tell the cluster that the location of one resource
depends on the location of another one.

Colocation has an important side-effect: it affects the order in which
resources are assigned to a node. Think about it: You can't place A relative to
B unless you know where B is [#]_.

So when you are creating colocation constraints, it is important to
consider whether you should colocate A with B, or B with A.

.. important::

   Colocation constraints affect *only* the placement of resources; they do *not*
   require that the resources be started in a particular order. If you want
   resources to be started on the same node *and* in a specific order, you need
   both an ordering constraint (see :ref:`s-resource-ordering`) *and* a colocation
   constraint, or alternatively, a group (see :ref:`group-resources`).

.. index::
   pair: XML element; rsc_colocation
   single: constraint; rsc_colocation

Colocation Properties
_____________________

.. table:: **Attributes of a rsc_colocation Constraint**
   :class: longtable
   :widths: 2 2 5

   +----------------+----------------+--------------------------------------------------------+
   | Field          | Default        | Description                                            |
   +================+================+========================================================+
   | id             |                | .. index::                                             |
   |                |                |    single: rsc_colocation; attribute, id               |
   |                |                |    single: attribute; id (rsc_colocation)              |
   |                |                |    single: id; rsc_colocation attribute                |
   |                |                |                                                        |
   |                |                | A unique name for the constraint (required).           |
   +----------------+----------------+--------------------------------------------------------+
   | rsc            |                | .. index::                                             |
   |                |                |    single: rsc_colocation; attribute, rsc              |
   |                |                |    single: attribute; rsc (rsc_colocation)             |
   |                |                |    single: rsc; rsc_colocation attribute               |
   |                |                |                                                        |
   |                |                | The name of a resource that should be located          |
   |                |                | relative to ``with-rsc``. A colocation constraint must |
   |                |                | either contain at least one                            |
   |                |                | :ref:`resource set <s-resource-sets>`, or specify both |
   |                |                | ``rsc`` and ``with-rsc``.                              |
   +----------------+----------------+--------------------------------------------------------+
   | with-rsc       |                | .. index::                                             |
   |                |                |    single: rsc_colocation; attribute, with-rsc         |
   |                |                |    single: attribute; with-rsc (rsc_colocation)        |
   |                |                |    single: with-rsc; rsc_colocation attribute          |
   |                |                |                                                        |
   |                |                | The name of the resource used as the colocation        |
   |                |                | target. The cluster will decide where to put this      |
   |                |                | resource first and then decide where to put ``rsc``.   |
   |                |                | A colocation constraint must either contain at least   |
   |                |                | one :ref:`resource set <s-resource-sets>`, or specify  |
   |                |                | both ``rsc`` and ``with-rsc``.                         |
   +----------------+----------------+--------------------------------------------------------+
   | node-attribute | #uname         | .. index::                                             |
   |                |                |    single: rsc_colocation; attribute, node-attribute   |
   |                |                |    single: attribute; node-attribute (rsc_colocation)  |
   |                |                |    single: node-attribute; rsc_colocation attribute    |
   |                |                |                                                        |
   |                |                | If ``rsc`` and ``with-rsc`` are specified, this node   |
   |                |                | attribute must be the same on the node running ``rsc`` |
   |                |                | and the node running ``with-rsc`` for the constraint   |
   |                |                | to be satisfied. (For details, see                     |
   |                |                | :ref:`s-coloc-attribute`.)                             |
   +----------------+----------------+--------------------------------------------------------+
   | score          | 0              | .. index::                                             |
   |                |                |    single: rsc_colocation; attribute, score            |
   |                |                |    single: attribute; score (rsc_colocation)           |
   |                |                |    single: score; rsc_colocation attribute             |
   |                |                |                                                        |
   |                |                | Positive values indicate the resources should run on   |
   |                |                | the same node. Negative values indicate the resources  |
   |                |                | should run on different nodes. Values of               |
   |                |                | +/- ``INFINITY`` change "should" to "must".            |
   +----------------+----------------+--------------------------------------------------------+
   | rsc-role       | Started        | .. index::                                             |
   |                |                |    single: clone; ordering constraint, rsc-role        |
   |                |                |    single: ordering constraint; rsc-role (clone)       |
   |                |                |    single: rsc-role; clone ordering constraint         |
   |                |                |                                                        |
   |                |                | If ``rsc`` and ``with-rsc`` are specified, and ``rsc`` |
   |                |                | is a :ref:`promotable clone <s-resource-promotable>`,  |
   |                |                | the constraint applies only to ``rsc`` instances in    |
   |                |                | this role. Allowed values: ``Started``, ``Promoted``,  |
   |                |                | ``Unpromoted``. For details, see                       |
   |                |                | :ref:`promotable-clone-constraints`.                   |
   +----------------+----------------+--------------------------------------------------------+
   | with-rsc-role  | Started        | .. index::                                             |
   |                |                |    single: clone; ordering constraint, with-rsc-role   |
   |                |                |    single: ordering constraint; with-rsc-role (clone)  |
   |                |                |    single: with-rsc-role; clone ordering constraint    |
   |                |                |                                                        |
   |                |                | If ``rsc`` and ``with-rsc`` are specified, and         |
   |                |                | ``with-rsc`` is a                                      |
   |                |                | :ref:`promotable clone <s-resource-promotable>`, the   |
   |                |                | constraint applies only to ``with-rsc`` instances in   |
   |                |                | this role. Allowed values: ``Started``, ``Promoted``,  |
   |                |                | ``Unpromoted``. For details, see                       |
   |                |                | :ref:`promotable-clone-constraints`.                   |
   +----------------+----------------+--------------------------------------------------------+
   | influence      | value of       | .. index::                                             |
   |                | ``critical``   |    single: rsc_colocation; attribute, influence        |
   |                | meta-attribute |    single: attribute; influence (rsc_colocation)       |
   |                | for ``rsc``    |    single: influence; rsc_colocation attribute         |
   |                |                |                                                        |
   |                |                | Whether to consider the location preferences of        |
   |                |                | ``rsc`` when ``with-rsc`` is already active. Allowed   |
   |                |                | values: ``true``, ``false``. For details, see          |
   |                |                | :ref:`s-coloc-influence`. *(since 2.1.0)*              |
   +----------------+----------------+--------------------------------------------------------+

Mandatory Placement
___________________

Mandatory placement occurs when the constraint's score is
**+INFINITY** or **-INFINITY**.  In such cases, if the constraint can't be
satisfied, then the **rsc** resource is not permitted to run.  For
``score=INFINITY``, this includes cases where the ``with-rsc`` resource is
not active.

If you need resource **A** to always run on the same machine as
resource **B**, you would add the following constraint:

.. topic:: Mandatory colocation constraint for two resources

   .. code-block:: xml

      <rsc_colocation id="colocate" rsc="A" with-rsc="B" score="INFINITY"/>

Remember, because **INFINITY** was used, if **B** can't run on any
of the cluster nodes (for whatever reason) then **A** will not
be allowed to run. Whether **A** is running or not has no effect on **B**.

Alternatively, you may want the opposite -- that **A** *cannot*
run on the same machine as **B**.  In this case, use ``score="-INFINITY"``.

.. topic:: Mandatory anti-colocation constraint for two resources

   .. code-block:: xml

      <rsc_colocation id="anti-colocate" rsc="A" with-rsc="B" score="-INFINITY"/>

Again, by specifying **-INFINITY**, the constraint is binding.  So if the
only place left to run is where **B** already is, then **A** may not run anywhere.

As with **INFINITY**, **B** can run even if **A** is stopped.  However, in this
case **A** also can run if **B** is stopped, because it still meets the
constraint of **A** and **B** not running on the same node.

Advisory Placement
__________________

If mandatory placement is about "must" and "must not", then advisory
placement is the "I'd prefer if" alternative.

For colocation constraints with scores greater than **-INFINITY** and less than
**INFINITY**, the cluster will try to accommodate your wishes, but may ignore
them if other factors outweigh the colocation score. Those factors might
include other constraints, resource stickiness, failure thresholds, whether
other resources would be prevented from being active, etc.

.. topic:: Advisory colocation constraint for two resources

   .. code-block:: xml

      <rsc_colocation id="colocate-maybe" rsc="A" with-rsc="B" score="500"/>

.. _s-coloc-attribute:

Colocation by Node Attribute
____________________________

The ``node-attribute`` property of a colocation constraints allows you to express
the requirement, "these resources must be on similar nodes".

As an example, imagine that you have two Storage Area Networks (SANs) that are
not controlled by the cluster, and each node is connected to one or the other.
You may have two resources **r1** and **r2** such that **r2** needs to use the same
SAN as **r1**, but doesn't necessarily have to be on the same exact node.
In such a case, you could define a :ref:`node attribute <node_attributes>` named
**san**, with the value **san1** or **san2** on each node as appropriate. Then, you
could colocate **r2** with **r1** using ``node-attribute`` set to **san**.

.. _s-coloc-influence:

Colocation Influence
____________________

By default, if A is colocated with B, the cluster will take into account A's
preferences when deciding where to place B, to maximize the chance that both
resources can run.

For a detailed look at exactly how this occurs, see
`Colocation Explained <http://clusterlabs.org/doc/Colocation_Explained.pdf>`_.

However, if ``influence`` is set to ``false`` in the colocation constraint,
this will happen only if B is inactive and needing to be started. If B is
already active, A's preferences will have no effect on placing B.

An example of what effect this would have and when it would be desirable would
be a nonessential reporting tool colocated with a resource-intensive service
that takes a long time to start. If the reporting tool fails enough times to
reach its migration threshold, by default the cluster will want to move both
resources to another node if possible. Setting ``influence`` to ``false`` on
the colocation constraint would mean that the reporting tool would be stopped
in this situation instead, to avoid forcing the service to move.

The ``critical`` resource meta-attribute is a convenient way to specify the
default for all colocation constraints and groups involving a particular
resource.

.. note::

   If a noncritical resource is a member of a group, all later members of the
   group will be treated as noncritical, even if they are marked as (or left to
   default to) critical.


.. _s-resource-sets:

Resource Sets
#############

.. index::
   single: constraint; resource set
   single: resource; resource set

*Resource sets* allow multiple resources to be affected by a single constraint.

.. topic:: A set of 3 resources

   .. code-block:: xml

      <resource_set id="resource-set-example">
          <resource_ref id="A"/>
          <resource_ref id="B"/>
          <resource_ref id="C"/>
      </resource_set>

Resource sets are valid inside ``rsc_location``, ``rsc_order``
(see :ref:`s-resource-sets-ordering`), ``rsc_colocation``
(see :ref:`s-resource-sets-colocation`), and ``rsc_ticket``
(see :ref:`ticket-constraints`) constraints.

A resource set has a number of properties that can be set, though not all
have an effect in all contexts.

.. index::
   pair: XML element; resource_set

.. table:: **Attributes of a resource_set Element**
   :class: longtable
   :widths: 2 2 5

   +-------------+------------------+--------------------------------------------------------+
   | Field       | Default          | Description                                            |
   +=============+==================+========================================================+
   | id          |                  | .. index::                                             |
   |             |                  |    single: resource_set; attribute, id                 |
   |             |                  |    single: attribute; id (resource_set)                |
   |             |                  |    single: id; resource_set attribute                  |
   |             |                  |                                                        |
   |             |                  | A unique name for the set (required)                   |
   +-------------+------------------+--------------------------------------------------------+
   | sequential  | true             | .. index::                                             |
   |             |                  |    single: resource_set; attribute, sequential         |
   |             |                  |    single: attribute; sequential (resource_set)        |
   |             |                  |    single: sequential; resource_set attribute          |
   |             |                  |                                                        |
   |             |                  | Whether the members of the set must be acted on in     |
   |             |                  | order.  Meaningful within ``rsc_order`` and            |
   |             |                  | ``rsc_colocation``.                                    |
   +-------------+------------------+--------------------------------------------------------+
   | require-all | true             | .. index::                                             |
   |             |                  |    single: resource_set; attribute, require-all        |
   |             |                  |    single: attribute; require-all (resource_set)       |
   |             |                  |    single: require-all; resource_set attribute         |
   |             |                  |                                                        |
   |             |                  | Whether all members of the set must be active before   |
   |             |                  | continuing.  With the current implementation, the      |
   |             |                  | cluster may continue even if only one member of the    |
   |             |                  | set is started, but if more than one member of the set |
   |             |                  | is starting at the same time, the cluster will still   |
   |             |                  | wait until all of those have started before continuing |
   |             |                  | (this may change in future versions).  Meaningful      |
   |             |                  | within ``rsc_order``.                                  |
   +-------------+------------------+--------------------------------------------------------+
   | role        |                  | .. index::                                             |
   |             |                  |    single: resource_set; attribute, role               |
   |             |                  |    single: attribute; role (resource_set)              |
   |             |                  |    single: role; resource_set attribute                |
   |             |                  |                                                        |
   |             |                  | The constraint applies only to resource set members    |
   |             |                  | that are :ref:`s-resource-promotable` in this          |
   |             |                  | role.  Meaningful within ``rsc_location``,             |
   |             |                  | ``rsc_colocation`` and ``rsc_ticket``.                 |
   |             |                  | Allowed values: ``Started``, ``Promoted``,             |
   |             |                  | ``Unpromoted``. For details, see                       |
   |             |                  | :ref:`promotable-clone-constraints`.                   |
   +-------------+------------------+--------------------------------------------------------+
   | action      | value of         | .. index::                                             |
   |             | ``first-action`` |    single: resource_set; attribute, action             |
   |             | in the enclosing |    single: attribute; action (resource_set)            |
   |             | ordering         |    single: action; resource_set attribute              |
   |             | constraint       |                                                        |
   |             |                  | The action that applies to *all members* of the set.   |
   |             |                  | Meaningful within ``rsc_order``. Allowed values:       |
   |             |                  | ``start``, ``stop``, ``promote``, ``demote``.          |
   +-------------+------------------+--------------------------------------------------------+
   | score       |                  | .. index::                                             |
   |             |                  |    single: resource_set; attribute, score              |
   |             |                  |    single: attribute; score (resource_set)             |
   |             |                  |    single: score; resource_set attribute               |
   |             |                  |                                                        |
   |             |                  | *Advanced use only.* Use a specific score for this     |
   |             |                  | set within the constraint.                             |
   +-------------+------------------+--------------------------------------------------------+

.. _s-resource-sets-ordering:

Ordering Sets of Resources
##########################

A common situation is for an administrator to create a chain of ordered
resources, such as:

.. topic:: A chain of ordered resources

   .. code-block:: xml

      <constraints>
          <rsc_order id="order-1" first="A" then="B" />
          <rsc_order id="order-2" first="B" then="C" />
          <rsc_order id="order-3" first="C" then="D" />
      </constraints>

.. topic:: Visual representation of the four resources' start order for the above constraints

   .. image:: images/resource-set.png
      :alt: Ordered set

Ordered Set
___________

To simplify this situation, :ref:`s-resource-sets` can be used within ordering
constraints:

.. topic:: A chain of ordered resources expressed as a set

   .. code-block:: xml

      <constraints>
          <rsc_order id="order-1">
            <resource_set id="ordered-set-example" sequential="true">
              <resource_ref id="A"/>
              <resource_ref id="B"/>
              <resource_ref id="C"/>
              <resource_ref id="D"/>
            </resource_set>
          </rsc_order>
      </constraints>

While the set-based format is not less verbose, it is significantly easier to
get right and maintain.

.. important::

   If you use a higher-level tool, pay attention to how it exposes this
   functionality. Depending on the tool, creating a set **A B** may be equivalent to
   **A then B**, or **B then A**.

Ordering Multiple Sets
______________________

The syntax can be expanded to allow sets of resources to be ordered relative to
each other, where the members of each individual set may be ordered or
unordered (controlled by the ``sequential`` property). In the example below, **A**
and **B** can both start in parallel, as can **C** and **D**, however **C** and
**D** can only start once *both* **A** *and* **B** are active.

.. topic:: Ordered sets of unordered resources

   .. code-block:: xml

      <constraints>
          <rsc_order id="order-1">
              <resource_set id="ordered-set-1" sequential="false">
                  <resource_ref id="A"/>
                  <resource_ref id="B"/>
              </resource_set>
              <resource_set id="ordered-set-2" sequential="false">
                  <resource_ref id="C"/>
                  <resource_ref id="D"/>
              </resource_set>
          </rsc_order>
      </constraints>

.. topic:: Visual representation of the start order for two ordered sets of
           unordered resources

   .. image:: images/two-sets.png
      :alt: Two ordered sets

Of course either set -- or both sets -- of resources can also be internally
ordered (by setting ``sequential="true"``) and there is no limit to the number
of sets that can be specified.

.. topic:: Advanced use of set ordering - Three ordered sets, two of which are
           internally unordered

   .. code-block:: xml

      <constraints>
          <rsc_order id="order-1">
            <resource_set id="ordered-set-1" sequential="false">
              <resource_ref id="A"/>
              <resource_ref id="B"/>
            </resource_set>
            <resource_set id="ordered-set-2" sequential="true">
              <resource_ref id="C"/>
              <resource_ref id="D"/>
            </resource_set>
            <resource_set id="ordered-set-3" sequential="false">
              <resource_ref id="E"/>
              <resource_ref id="F"/>
            </resource_set>
          </rsc_order>
      </constraints>

.. topic:: Visual representation of the start order for the three sets defined above

   .. image:: images/three-sets.png
      :alt: Three ordered sets

.. important::

   An ordered set with ``sequential=false`` makes sense only if there is another
   set in the constraint. Otherwise, the constraint has no effect.

Resource Set OR Logic
_____________________

The unordered set logic discussed so far has all been "AND" logic.  To illustrate
this take the 3 resource set figure in the previous section.  Those sets can be
expressed, **(A and B) then (C) then (D) then (E and F)**.

Say for example we want to change the first set, **(A and B)**, to use "OR" logic
so the sets look like this: **(A or B) then (C) then (D) then (E and F)**.  This
functionality can be achieved through the use of the ``require-all`` option.
This option defaults to TRUE which is why the "AND" logic is used by default.
Setting ``require-all=false`` means only one resource in the set needs to be
started before continuing on to the next set.

.. topic:: Resource Set "OR" logic: Three ordered sets, where the first set is
           internally unordered with "OR" logic

   .. code-block:: xml

      <constraints>
          <rsc_order id="order-1">
            <resource_set id="ordered-set-1" sequential="false" require-all="false">
              <resource_ref id="A"/>
              <resource_ref id="B"/>
            </resource_set>
            <resource_set id="ordered-set-2" sequential="true">
              <resource_ref id="C"/>
              <resource_ref id="D"/>
            </resource_set>
            <resource_set id="ordered-set-3" sequential="false">
              <resource_ref id="E"/>
              <resource_ref id="F"/>
            </resource_set>
          </rsc_order>
      </constraints>

.. important::

   An ordered set with ``require-all=false`` makes sense only in conjunction with
   ``sequential=false``. Think of it like this: ``sequential=false`` modifies the set
   to be an unordered set using "AND" logic by default, and adding
   ``require-all=false`` flips the unordered set's "AND" logic to "OR" logic.

.. _s-resource-sets-colocation:

Colocating Sets of Resources
############################

Another common situation is for an administrator to create a set of
colocated resources.

The simplest way to do this is to define a resource group (see
:ref:`group-resources`), but that cannot always accurately express the desired
relationships. For example, maybe the resources do not need to be ordered.

Another way would be to define each relationship as an individual constraint,
but that causes a difficult-to-follow constraint explosion as the number of
resources and combinations grow.

.. topic:: Colocation chain as individual constraints, where A is placed first,
           then B, then C, then D

   .. code-block:: xml

      <constraints>
          <rsc_colocation id="coloc-1" rsc="D" with-rsc="C" score="INFINITY"/>
          <rsc_colocation id="coloc-2" rsc="C" with-rsc="B" score="INFINITY"/>
          <rsc_colocation id="coloc-3" rsc="B" with-rsc="A" score="INFINITY"/>
      </constraints>

To express complicated relationships with a simplified syntax [#]_,
:ref:`resource sets <s-resource-sets>` can be used within colocation constraints.

.. topic:: Equivalent colocation chain expressed using **resource_set**

   .. code-block:: xml

      <constraints>
          <rsc_colocation id="coloc-1" score="INFINITY" >
            <resource_set id="colocated-set-example" sequential="true">
              <resource_ref id="A"/>
              <resource_ref id="B"/>
              <resource_ref id="C"/>
              <resource_ref id="D"/>
            </resource_set>
          </rsc_colocation>
      </constraints>

.. note::

   Within a ``resource_set``, the resources are listed in the order they are
   *placed*, which is the reverse of the order in which they are *colocated*.
   In the above example, resource **A** is placed before resource **B**, which is
   the same as saying resource **B** is colocated with resource **A**.

As with individual constraints, a resource that can't be active prevents any
resource that must be colocated with it from being active. In both of the two
previous examples, if **B** is unable to run, then both **C** and by inference **D**
must remain stopped.

.. important::

   If you use a higher-level tool, pay attention to how it exposes this
   functionality. Depending on the tool, creating a set **A B** may be equivalent to
   **A with B**, or **B with A**.

Resource sets can also be used to tell the cluster that entire *sets* of
resources must be colocated relative to each other, while the individual
members within any one set may or may not be colocated relative to each other
(determined by the set's ``sequential`` property).

In the following example, resources **B**, **C**, and **D** will each be colocated
with **A** (which will be placed first). **A** must be able to run in order for any
of the resources to run, but any of **B**, **C**, or **D** may be stopped without
affecting any of the others.

.. topic:: Using colocated sets to specify a shared dependency

   .. code-block:: xml

      <constraints>
          <rsc_colocation id="coloc-1" score="INFINITY" >
            <resource_set id="colocated-set-2" sequential="false">
              <resource_ref id="B"/>
              <resource_ref id="C"/>
              <resource_ref id="D"/>
            </resource_set>
            <resource_set id="colocated-set-1" sequential="true">
              <resource_ref id="A"/>
            </resource_set>
          </rsc_colocation>
      </constraints>

.. note::

   Pay close attention to the order in which resources and sets are listed.
   While the members of any one sequential set are placed first to last (i.e., the
   colocation dependency is last with first), multiple sets are placed last to
   first (i.e. the colocation dependency is first with last).

.. important::

   A colocated set with ``sequential="false"`` makes sense only if there is
   another set in the constraint. Otherwise, the constraint has no effect.

There is no inherent limit to the number and size of the sets used.
The only thing that matters is that in order for any member of one set
in the constraint to be active, all members of sets listed after it must also
be active (and naturally on the same node); and if a set has ``sequential="true"``,
then in order for one member of that set to be active, all members listed
before it must also be active.

If desired, you can restrict the dependency to instances of promotable clone
resources that are in a specific role, using the set's ``role`` property.

.. topic:: Colocation in which the members of the middle set have no
           interdependencies, and the last set listed applies only to promoted
           instances

   .. code-block:: xml

      <constraints>
          <rsc_colocation id="coloc-1" score="INFINITY" >
            <resource_set id="colocated-set-1" sequential="true">
              <resource_ref id="F"/>
              <resource_ref id="G"/>
            </resource_set>
            <resource_set id="colocated-set-2" sequential="false">
              <resource_ref id="C"/>
              <resource_ref id="D"/>
              <resource_ref id="E"/>
            </resource_set>
            <resource_set id="colocated-set-3" sequential="true" role="Promoted">
              <resource_ref id="A"/>
              <resource_ref id="B"/>
            </resource_set>
          </rsc_colocation>
      </constraints>

.. topic:: Visual representation of the above example (resources are placed from
           left to right)

   .. image:: ../shared/images/pcmk-colocated-sets.png
      :alt: Colocation chain

.. note::

   Unlike ordered sets, colocated sets do not use the ``require-all`` option.

.. [#] While the human brain is sophisticated enough to read the constraint
       in any order and choose the correct one depending on the situation,
       the cluster is not quite so smart. Yet.

.. [#] which is not the same as saying easy to follow
