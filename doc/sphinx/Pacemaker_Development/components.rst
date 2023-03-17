Coding Particular Pacemaker Components
--------------------------------------

The Pacemaker code can be intricate and difficult to follow. This chapter has
some high-level descriptions of how individual components work.


.. index::
   single: controller
   single: pacemaker-controld

Controller
##########

``pacemaker-controld`` is the Pacemaker daemon that utilizes the other daemons
to orchestrate actions that need to be taken in the cluster. It receives CIB
change notifications from the CIB manager, passes the new CIB to the scheduler
to determine whether anything needs to be done, uses the executor and fencer to
execute any actions required, and sets failure counts (among other things) via
the attribute manager.

As might be expected, it has the most code of any of the daemons.

.. index::
   single: join

Join sequence
_____________

Most daemons track their cluster peers using Corosync's membership and CPG
only. The controller additionally requires peers to `join`, which ensures they
are ready to be assigned tasks. Joining proceeds through a series of phases
referred to as the `join sequence` or `join process`.

A node's current join phase is tracked by the ``join`` member of ``crm_node_t``
(used in the peer cache). It is an ``enum crm_join_phase`` that (ideally)
progresses from the DC's point of view as follows:

* The node initially starts at ``crm_join_none``

* The DC sends the node a `join offer` (``CRM_OP_JOIN_OFFER``), and the node
  proceeds to ``crm_join_welcomed``. This can happen in three ways:
  
  * The joining node will send a `join announce` (``CRM_OP_JOIN_ANNOUNCE``) at
    its controller startup, and the DC will reply to that with a join offer.
  * When the DC's peer status callback notices that the node has joined the
    messaging layer, it registers ``I_NODE_JOIN`` (which leads to
    ``A_DC_JOIN_OFFER_ONE`` -> ``do_dc_join_offer_one()`` ->
    ``join_make_offer()``).
  * After certain events (notably a new DC being elected), the DC will send all
    nodes join offers (via A_DC_JOIN_OFFER_ALL -> ``do_dc_join_offer_all()``).

  These can overlap. The DC can send a join offer and the node can send a join
  announce at nearly the same time, so the node responds to the original join
  offer while the DC responds to the join announce with a new join offer. The
  situation resolves itself after looping a bit.

* The node responds to join offers with a `join request`
  (``CRM_OP_JOIN_REQUEST``, via ``do_cl_join_offer_respond()`` and
  ``join_query_callback()``). When the DC receives the request, the
  node proceeds to ``crm_join_integrated`` (via ``do_dc_join_filter_offer()``).

* As each node is integrated, the current best CIB is sync'ed to each
  integrated node via ``do_dc_join_finalize()``. As each integrated node's CIB
  sync succeeds, the DC acks the node's join request (``CRM_OP_JOIN_ACKNAK``)
  and the node proceeds to ``crm_join_finalized`` (via
  ``finalize_sync_callback()`` + ``finalize_join_for()``).

* Each node confirms the finalization ack (``CRM_OP_JOIN_CONFIRM`` via
  ``do_cl_join_finalize_respond()``), including its current resource operation
  history (via ``controld_query_executor_state()``). Once the DC receives this
  confirmation, the node proceeds to ``crm_join_confirmed`` via
  ``do_dc_join_ack()``.

Once all nodes are confirmed, the DC calls ``do_dc_join_final()``, which checks
for quorum and responds appropriately.

When peers are lost, their join phase is reset to none (in various places).

``crm_update_peer_join()`` updates a node's join phase.

The DC increments the global ``current_join_id`` for each joining round, and
rejects any (older) replies that don't match.


.. index::
   single: fencer
   single: pacemaker-fenced

Fencer
######

``pacemaker-fenced`` is the Pacemaker daemon that handles fencing requests. In
the broadest terms, fencing works like this:

#. The initiator (an external program such as ``stonith_admin``, or the cluster
   itself via the controller) asks the local fencer, "Hey, could you please
   fence this node?"
#. The local fencer asks all the fencers in the cluster (including itself),
   "Hey, what fencing devices do you have access to that can fence this node?"
#. Each fencer in the cluster replies with a list of available devices that
   it knows about.
#. Once the original fencer gets all the replies, it asks the most
   appropriate fencer peer to actually carry out the fencing. It may send
   out more than one such request if the target node must be fenced with
   multiple devices.
#. The chosen fencer(s) call the appropriate fencing resource agent(s) to
   do the fencing, then reply to the original fencer with the result.
#. The original fencer broadcasts the result to all fencers.
#. Each fencer sends the result to each of its local clients (including, at
   some point, the initiator).

A more detailed description follows.

.. index::
   single: libstonithd

Initiating a fencing request
____________________________

A fencing request can be initiated by the cluster or externally, using the
libstonithd API.

* The cluster always initiates fencing via
  ``daemons/controld/controld_fencing.c:te_fence_node()`` (which calls the
  ``fence()`` API method). This occurs when a transition graph synapse contains
  a ``CRM_OP_FENCE`` XML operation.
* The main external clients are ``stonith_admin`` and ``cts-fence-helper``.
  The ``DLM`` project also uses Pacemaker for fencing.

Highlights of the fencing API:

* ``stonith_api_new()`` creates and returns a new ``stonith_t`` object, whose
  ``cmds`` member has methods for connect, disconnect, fence, etc.
* the ``fence()`` method creates and sends a ``STONITH_OP_FENCE XML`` request with
  the desired action and target node. Callers do not have to choose or even
  have any knowledge about particular fencing devices.

Fencing queries
_______________

The function calls for a fencing request go something like this:

The local fencer receives the client's request via an IPC or messaging
layer callback, which calls

* ``stonith_command()``, which (for requests) calls

  * ``handle_request()``, which (for ``STONITH_OP_FENCE`` from a client) calls

    * ``initiate_remote_stonith_op()``, which creates a ``STONITH_OP_QUERY`` XML
      request with the target, desired action, timeout, etc. then broadcasts
      the operation to the cluster group (i.e. all fencer instances) and
      starts a timer. The query is broadcast because (1) location constraints
      might prevent the local node from accessing the stonith device directly,
      and (2) even if the local node does have direct access, another node
      might be preferred to carry out the fencing.

Each fencer receives the original fencer's ``STONITH_OP_QUERY`` broadcast
request via IPC or messaging layer callback, which calls:

* ``stonith_command()``, which (for requests) calls

  *  ``handle_request()``, which (for ``STONITH_OP_QUERY`` from a peer) calls

    * ``stonith_query()``, which calls

      * ``get_capable_devices()`` with ``stonith_query_capable_device_cb()`` to add
        device information to an XML reply and send it. (A message is
        considered a reply if it contains ``T_STONITH_REPLY``, which is only
        set by fencer peers, not clients.)

The original fencer receives all peers' ``STONITH_OP_QUERY`` replies via IPC
or messaging layer callback, which calls:

* ``stonith_command()``, which (for replies) calls

  * ``handle_reply()`` which (for ``STONITH_OP_QUERY``) calls

    * ``process_remote_stonith_query()``, which allocates a new query result
      structure, parses device information into it, and adds it to the
      operation object. It increments the number of replies received for this
      operation, and compares it against the expected number of replies (i.e.
      the number of active peers), and if this is the last expected reply,
      calls

      * ``request_peer_fencing()``, which calculates the timeout and sends
        ``STONITH_OP_FENCE`` request(s) to carry out the fencing. If the target
	node has a fencing "topology" (which allows specifications such as
	"this node can be fenced either with device A, or devices B and C in
	combination"), it will choose the device(s), and send out as many
	requests as needed. If it chooses a device, it will choose the peer; a
	peer is preferred if it has "verified" access to the desired device,
	meaning that it has the device "running" on it and thus has a monitor
        operation ensuring reachability.

Fencing operations
__________________

Each ``STONITH_OP_FENCE`` request goes something like this:

The chosen peer fencer receives the ``STONITH_OP_FENCE`` request via IPC or
messaging layer callback, which calls:

* ``stonith_command()``, which (for requests) calls

  * ``handle_request()``, which (for ``STONITH_OP_FENCE`` from a peer) calls

    * ``stonith_fence()``, which calls

      * ``schedule_stonith_command()`` (using supplied device if
        ``F_STONITH_DEVICE`` was set, otherwise the highest-priority capable
	device obtained via ``get_capable_devices()`` with
	``stonith_fence_get_devices_cb()``), which adds the operation to the
        device's pending operations list and triggers processing.

The chosen peer fencer's mainloop is triggered and calls

* ``stonith_device_dispatch()``, which calls

  * ``stonith_device_execute()``, which pops off the next item from the device's
    pending operations list. If acting as the (internally implemented) watchdog
    agent, it panics the node, otherwise it calls

    * ``stonith_action_create()`` and ``stonith_action_execute_async()`` to
      call the fencing agent.

The chosen peer fencer's mainloop is triggered again once the fencing agent
returns, and calls

* ``stonith_action_async_done()`` which adds the results to an action object
  then calls its

  * done callback (``st_child_done()``), which calls ``schedule_stonith_command()``
    for a new device if there are further required actions to execute or if the
    original action failed, then builds and sends an XML reply to the original
    fencer (via ``send_async_reply()``), then checks whether any
    pending actions are the same as the one just executed and merges them if so.

Fencing replies
_______________

The original fencer receives the ``STONITH_OP_FENCE`` reply via IPC or
messaging layer callback, which calls:

* ``stonith_command()``, which (for replies) calls

  * ``handle_reply()``, which calls

    * ``fenced_process_fencing_reply()``, which calls either
      ``request_peer_fencing()`` (to retry a failed operation, or try the next
      device in a topology if appropriate, which issues a new
      ``STONITH_OP_FENCE`` request, proceeding as before) or
      ``finalize_op()`` (if the operation is definitively failed or
      successful).

      * ``finalize_op()`` broadcasts the result to all peers.

Finally, all peers receive the broadcast result and call

* ``finalize_op()``, which sends the result to all local clients.


.. index::
   single: fence history

Fencing History
_______________

The fencer keeps a running history of all fencing operations. The bulk of the
relevant code is in `fenced_history.c` and ensures the history is synchronized
across all nodes even if a node leaves and rejoins the cluster.

In libstonithd, this information is represented by `stonith_history_t` and is
queryable by the `stonith_api_operations_t:history()` method. `crm_mon` and
`stonith_admin` use this API to display the history.


.. index::
   single: scheduler
   single: pacemaker-schedulerd
   single: libpe_status
   single: libpe_rules
   single: libpacemaker

Scheduler
#########

``pacemaker-schedulerd`` is the Pacemaker daemon that runs the Pacemaker
scheduler for the controller, but "the scheduler" in general refers to related
library code in ``libpe_status`` and ``libpe_rules`` (``lib/pengine/*.c``), and
some of ``libpacemaker`` (``lib/pacemaker/pcmk_sched_*.c``).

The purpose of the scheduler is to take a CIB as input and generate a
transition graph (list of actions that need to be taken) as output.

The controller invokes the scheduler by contacting the scheduler daemon via
local IPC. Tools such as ``crm_simulate``, ``crm_mon``, and ``crm_resource``
can also invoke the scheduler, but do so by calling the library functions
directly. This allows them to run using a ``CIB_file`` without the cluster
needing to be active.

The main entry point for the scheduler code is
``lib/pacemaker/pcmk_sched_allocate.c:pcmk__schedule_actions()``. It sets
defaults and calls a series of functions for the scheduling. Some key steps:

* ``unpack_cib()`` parses most of the CIB XML into data structures, and
  determines the current cluster status.
* ``apply_node_criteria()`` applies factors that make resources prefer certain
  nodes, such as shutdown locks, location constraints, and stickiness.
* ``pcmk__create_internal_constraints()`` creates internal constraints, such as
  the implicit ordering for group members, or start actions being implicitly
  ordered before promote actions.
* ``pcmk__handle_rsc_config_changes()`` processes resource history entries in
  the CIB status section. This is used to decide whether certain
  actions need to be done, such as deleting orphan resources, forcing a restart
  when a resource definition changes, etc.
* ``allocate_resources()`` assigns resources to nodes.
* ``schedule_resource_actions()`` schedules resource-specific actions (which
  might or might not end up in the final graph).
* ``pcmk__apply_orderings()`` processes ordering constraints in order to modify
  action attributes such as optional or required.
* ``pcmk__create_graph()`` creates the transition graph.

Challenges
__________

Working with the scheduler is difficult. Challenges include:

* It is far too much code to keep more than a small portion in your head at one
  time.
* Small changes can have large (and unexpected) effects. This is why we have a
  large number of regression tests (``cts/cts-scheduler``), which should be run
  after making code changes.
* It produces an insane amount of log messages at debug and trace levels.
  You can put resource ID(s) in the ``PCMK_trace_tags`` environment variable to
  enable trace-level messages only when related to specific resources.
* Different parts of the main ``pe_working_set_t`` structure are finalized at
  different points in the scheduling process, so you have to keep in mind
  whether information you're using at one point of the code can possibly change
  later. For example, data unpacked from the CIB can safely be used anytime
  after ``unpack_cib(),`` but actions may become optional or required anytime
  before ``pcmk__create_graph()``. There's no easy way to deal with this.
* Many names of struct members, functions, etc., are suboptimal, but are part
  of the public API and cannot be changed until an API backward compatibility
  break.


.. index::
   single: pe_working_set_t

Cluster Working Set
___________________

The main data object for the scheduler is ``pe_working_set_t``, which contains
all information needed about nodes, resources, constraints, etc., both as the
raw CIB XML and parsed into more usable data structures, plus the resulting
transition graph XML. The variable name is usually ``data_set``.

.. index::
   single: pe_resource_t

Resources
_________

``pe_resource_t`` is the data object representing cluster resources. A resource
has a variant: primitive (a.k.a. native), group, clone, or bundle.

The resource object has members for two sets of methods,
``resource_object_functions_t`` from the ``libpe_status`` public API, and
``resource_alloc_functions_t`` whose implementation is internal to
``libpacemaker``. The actual functions vary by variant.

The object functions have basic capabilities such as unpacking the resource
XML, and determining the current or planned location of the resource.

The allocation functions have more obscure capabilities needed for scheduling,
such as processing location and ordering constraints. For example,
``pcmk__create_internal_constraints()`` simply calls the
``internal_constraints()`` method for each top-level resource in the cluster.

.. index::
   single: pe_node_t

Nodes
_____

Allocation of resources to nodes is done by choosing the node with the highest
score for a given resource. The scheduler does a bunch of processing to
generate the scores, then the actual allocation is straightforward.

Node lists are frequently used. For example, ``pe_working_set_t`` has a
``nodes`` member which is a list of all nodes in the cluster, and
``pe_resource_t`` has a ``running_on`` member which is a list of all nodes on
which the resource is (or might be) active. These are lists of ``pe_node_t``
objects.

The ``pe_node_t`` object contains a ``struct pe_node_shared_s *details`` member
with all node information that is independent of resource allocation (the node
name, etc.).

The working set's ``nodes`` member contains the original of this information.
All other node lists contain copies of ``pe_node_t`` where only the ``details``
member points to the originals in the working set's ``nodes`` list. In this
way, the other members of ``pe_node_t`` (such as ``weight``, which is the node
score) may vary by node list, while the common details are shared.

.. index::
   single: pe_action_t
   single: pe_action_flags

Actions
_______

``pe_action_t`` is the data object representing actions that might need to be
taken. These could be resource actions, cluster-wide actions such as fencing a
node, or "pseudo-actions" which are abstractions used as convenient points for
ordering other actions against.

It has a ``flags`` member which is a bitmask of ``enum pe_action_flags``. The
most important of these are ``pe_action_runnable`` (if not set, the action is
"blocked" and cannot be added to the transition graph) and
``pe_action_optional`` (actions with this set will not be added to the
transition graph; actions often start out as optional, and may become required
later).


.. index::
   single: pe__colocation_t

Colocations
___________

``pcmk__colocation_t`` is the data object representing colocations.

Colocation constraints come into play in these parts of the scheduler code:

* When sorting resources for assignment, so resources with highest node score
  are assigned first (see ``cmp_resources()``)
* When updating node scores for resource assigment or promotion priority
* When assigning resources, so any resources to be colocated with can be
  assigned first, and so colocations affect where the resource is assigned
* When choosing roles for promotable clone instances, so colocations involving
  a specific role can affect which instances are promoted

The resource allocation functions have several methods related to colocations:

* ``apply_coloc_score():`` This applies a colocation's score to either the
  dependent's allowed node scores (if called while resources are being
  assigned) or the dependent's priority (if called while choosing promotable
  instance roles). It can behave differently depending on whether it is being
  called as the primary's method or as the dependent's method.
* ``add_colocated_node_scores():`` This updates a table of nodes for a given
  colocation attribute and score. It goes through colocations involving a given
  resource, and updates the scores of the nodes in the table with the best
  scores of nodes that match up according to the colocation criteria.
* ``colocated_resources():`` This generates a list of all resources involved
  in mandatory colocations (directly or indirectly via colocation chains) with
  a given resource.


.. index::
   single: pe__ordering_t
   single: pe_ordering

Orderings
_________

Ordering constraints are simple in concept, but they are one of the most
important, powerful, and difficult to follow aspects of the scheduler code.

``pe__ordering_t`` is the data object representing an ordering, better thought
of as a relationship between two actions, since the relation can be more
complex than just "this one runs after that one".

For an ordering "A then B", the code generally refers to A as "first" or
"before", and B as "then" or "after".

Much of the power comes from ``enum pe_ordering``, which are flags that
determine how an ordering behaves. There are many obscure flags with big
effects. A few examples:

* ``pe_order_none`` means the ordering is disabled and will be ignored. It's 0,
  meaning no flags set, so it must be compared with equality rather than
  ``pcmk_is_set()``.
* ``pe_order_optional`` means the ordering does not make either action
  required, so it only applies if they both become required for other reasons.
* ``pe_order_implies_first`` means that if action B becomes required for any
  reason, then action A will become required as well.
