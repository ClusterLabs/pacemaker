.. _utilization:

Utilization and Placement Strategy
----------------------------------

Pacemaker decides where a resource should run by assigning a score to every
node, considering factors such as the resource's constraints and stickiness,
then assigning the resource to the node with the highest score.

If more than one node has the highest score, Pacemaker by default chooses
the one with the least number of assigned resources, or if that is also the
same, the one listed first in the CIB. This results in simple load balancing.

Sometimes, simple load balancing is insufficient. Different resources can use
significantly different amounts of a node's memory, CPU, and other capacities.
Some combinations of resources may strain a node's capacity, causing them to
fail or have degraded performance. Or, an administrator may prefer to
concentrate resources rather than balance them, to minimize energy consumption
by spare nodes.

Pacemaker offers flexibility by allowing you to configure *utilization
attributes* specifying capacities that each node provides and each resource
requires, as well as a *placement strategy*.

Utilization attributes
######################

You can define any number of utilization attributes to represent capacities of
interest (CPU, memory, I/O bandwidth, etc.). Their values must be integers.

The nature and units of the capacities are irrelevant to Pacemaker. It just
makes sure that each node has sufficient capacity to run the resources assigned
to it.

.. topic:: Specifying CPU and RAM capacities of two nodes

   .. code-block:: xml

      <node id="node1" type="normal" uname="node1">
        <utilization id="node1-utilization">
          <nvpair id="node1-utilization-cpu" name="cpu" value="2"/>
          <nvpair id="node1-utilization-memory" name="memory" value="2048"/>
        </utilization>
      </node>
      <node id="node2" type="normal" uname="node2">
        <utilization id="node2-utilization">
          <nvpair id="node2-utilization-cpu" name="cpu" value="4"/>
          <nvpair id="node2-utilization-memory" name="memory" value="4096"/>
        </utilization>
      </node>

.. topic:: Specifying CPU and RAM consumed by several resources

   .. code-block:: xml

      <primitive id="rsc-small" class="ocf" provider="pacemaker" type="Dummy">
        <utilization id="rsc-small-utilization">
          <nvpair id="rsc-small-utilization-cpu" name="cpu" value="1"/>
          <nvpair id="rsc-small-utilization-memory" name="memory" value="1024"/>
        </utilization>
      </primitive>
      <primitive id="rsc-medium" class="ocf" provider="pacemaker" type="Dummy">
        <utilization id="rsc-medium-utilization">
          <nvpair id="rsc-medium-utilization-cpu" name="cpu" value="2"/>
          <nvpair id="rsc-medium-utilization-memory" name="memory" value="2048"/>
        </utilization>
      </primitive>
      <primitive id="rsc-large" class="ocf" provider="pacemaker" type="Dummy">
        <utilization id="rsc-large-utilization">
          <nvpair id="rsc-large-utilization-cpu" name="cpu" value="3"/>
          <nvpair id="rsc-large-utilization-memory" name="memory" value="3072"/>
        </utilization>
      </primitive>

Utilization attributes for a node may be permanent or *(since 2.1.6)*
transient. Permanent attributes persist after Pacemaker is restarted, while
transient attributes do not.

.. topic:: Transient utilization attribute for node cluster-1

   .. code-block:: xml

      <transient_attributes id="cluster-1">
        <utilization id="status-cluster-1">
          <nvpair id="status-cluster-1-cpu" name="cpu" value="1"/>
        </utilization>
      </transient_attributes>

Utilization attributes may be configured only on primitive resources. Pacemaker
will consider a collective resource's utilization based on the primitives it
contains.

.. note::

   Utilization is supported for bundles *(since 2.1.3)*, but only for bundles
   with an inner primitive.


Placement Strategy
##################

The ``placement-strategy`` cluster option determines how utilization attributes
are used. Its allowed values are:

* ``default``: The cluster ignores utilization values, and places resources
  according to (from highest to lowest precedence) assignment scores, the
  number of resources already assigned to each node, and the order nodes are
  listed in the CIB.

* ``utilization``: The cluster uses the same method as the default strategy to
  assign a resource to a node, but only nodes with sufficient free capacity to
  meet the resource's requirements are eligible.

* ``balanced``: Only nodes with sufficient free capacity are eligible to run a
  resource, and the cluster load-balances based on the sum of resource
  utilization values rather than the number of resources.

* ``minimal``: Only nodes with sufficient free capacity are eligible to run a
  resource, and the cluster concentrates resources on as few nodes as possible.


To look at it another way, when deciding where to run a resource, the cluster
starts by considering all nodes, then applies these criteria one by one until
a single node remains:

* If ``placement-strategy`` is ``utilization``, ``balanced``, or ``minimal``,
  consider only nodes that have sufficient spare capacities to meet the
  resource's requirements.

* Consider only nodes with the highest score for the resource. Scores take into
  account factors such as the node's health; the resource's stickiness, failure
  count on the node, and migration threshold; and constraints.

* If ``placement-strategy`` is ``balanced``, consider only nodes with the most
  free capacity.

* If ``placement-strategy`` is ``default``, ``utilization``, or ``balanced``,
  consider only nodes with the least number of assigned resources.

* If more than one node is eligible after considering all other criteria,
  choose the one listed first in the CIB.

How Multiple Capacities Combine
###############################

If only one type of utilization attribute has been defined, free capacity is a
simple numeric comparison.

If multiple utilization attributes have been defined, then the node that has
the highest value in the most attribute types has the most free capacity.

For example:

* If ``nodeA`` has more free ``cpus``, and ``nodeB`` has more free ``memory``,
  then their free capacities are equal.

* If ``nodeA`` has more free ``cpus``, while ``nodeB`` has more free ``memory``
  and ``storage``, then ``nodeB`` has more free capacity.

Order of Resource Assignment
############################

When assigning resources to nodes, the cluster chooses the next one to assign
by considering the following criteria one by one until a single resource is
selected:

* Assign the resource with the highest :ref:`priority <meta_priority>`.

* If any resources are already active, assign the one with the highest score on
  its current node. This avoids unnecessary resource shuffling.

* Assign the resource with the highest score on its preferred node.

* If more than one resource remains after considering all other criteria,
  assign the one of them that is listed first in the CIB.

.. note::

   For bundles, only the priority set for the bundle itself matters. If the
   bundle contains a primitive, the primitive's priority is ignored.

Limitations
###########

The type of problem Pacemaker is dealing with here is known as the
`knapsack problem <https://en.wikipedia.org/wiki/Knapsack_problem>`_ and falls
into the `NP-complete <https://en.wikipedia.org/wiki/NP-completeness>`_
category of computer science problems -- a fancy way of saying "it takes a
really long time to solve".

In a high-availability cluster, it is unacceptable to spend minutes, let alone
hours or days, finding an optimal solution while services are down.

Instead of trying to solve the problem completely, Pacemaker uses a "best
effort" algorithm. This arrives at a quick solution, but at the cost of
possibly leaving some resources stopped unnecessarily.

Using the example configuration at the start of this chapter, and the balanced
placement strategy:

* ``rsc-small`` would be assigned to ``node1``

* ``rsc-medium`` would be assigned to ``node2``

* ``rsc-large`` would remain inactive

That is not ideal. There are various approaches to dealing with the limitations
of Pacemaker's placement strategy:

* **Ensure you have sufficient physical capacity.**

   It might sound obvious, but if the physical capacity of your nodes is maxed
   out even under normal conditions, failover isn't going to go well. Even
   without the utilization feature, you'll start hitting timeouts and getting
   secondary failures.

* **Build some buffer into the capacities advertised by the nodes.**

   Advertise slightly more resources than we physically have, on the (usually
   valid) assumption that resources will not always use 100% of their
   configured utilization. This practice is sometimes called *overcommitting*.

* **Specify resource priorities.**

   If the cluster is going to sacrifice services, it should be the ones you
   care about the least.
