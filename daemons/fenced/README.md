# Directory contents

* `pacemaker-fenced.c`, `pacemaker-fenced.h`, `fenced_commands.c`,
  `fenced_remote.c`, `pacemaker-fenced.7`: pacemaker-fenced (the fencer) and
   its man page
* `fence_dummy`, `fence_legacy`, `fence_legacy.8`:
  Pacemaker-supplied fence agents and their man pages
* `cts-fence-helper.c`: `cts-fence-helper` command-line tool

# How fencing requests are handled

## Bird's eye view

In the broadest terms, stonith works like this:

1. The initiator (an external program such as `stonith_admin`, or the cluster
   itself via the controller) asks the local fencer, "Hey, can you fence this
   node?"
1. The local fencer asks all the fencers in the cluster (including
   itself), "Hey, what fencing devices do you have access to that can fence
   this node?"
1. Each fencer in the cluster replies with a list of available devices that
   it knows about.
1. Once the original fencer gets all the replies, it asks the most
   appropriate fencer peer to actually carry out the fencing. It may send
   out more than one such request if the target node must be fenced with
   multiple devices.
1. The chosen fencer(s) call the appropriate fencing resource agent(s) to
   do the fencing, then replies to the original fencer with the result.
1. The original fencer broadcasts the result to all fencers.
1. Each fencer sends the result to each of its local clients (including, at
   some point, the initiator).

## Detailed view

### Initiating a fencing request

A fencing request can be initiated by the cluster or externally, using the
libfencing API.

* The cluster always initiates fencing via
  `daemons/controld/controld_te_actions.c:te_fence_node()` (which calls the
  `fence()` API). This occurs when a graph synapse contains a `CRM_OP_FENCE`
  XML operation.
* The main external clients are `stonith_admin` and `cts-fence-helper`.

Highlights of the fencing API:
* `stonith_api_new()` creates and returns a new `stonith_t` object, whose
  `cmds` member has methods for connect, disconnect, fence, etc.
* the `fence()` method creates and sends a `STONITH_OP_FENCE XML` request with
  the desired action and target node. Callers do not have to choose or even
  have any knowledge about particular fencing devices.

### Fencing queries

The function calls for a stonith request go something like this as of this writing:

The local fencer receives the client's request via an IPC or messaging
layer callback, which calls
* `stonith_command()`, which (for requests) calls
  * `handle_request()`, which (for `STONITH_OP_FENCE` from a client) calls
    * `initiate_remote_stonith_op()`, which creates a `STONITH_OP_QUERY` XML
      request with the target, desired action, timeout, etc.. then broadcasts
      the operation to the cluster group (i.e. all fencer instances) and
      starts a timer. The query is broadcast because (1) location constraints
      might prevent the local node from accessing the stonith device directly,
      and (2) even if the local node does have direct access, another node
      might be preferred to carry out the fencing.

Each fencer receives the original fencer's STONITH_OP_QUERY` broadcast
request via IPC or messaging layer callback, which calls:
* `stonith_command()`, which (for requests) calls
  *  `handle_request()`, which (for `STONITH_OP_QUERY` from a peer) calls
    * `stonith_query()`, which calls
      * `get_capable_devices()` with `stonith_query_capable_device_db()` to add
        device information to an XML reply and send it. (A message is
	considered a reply if it contains `T_STONITH_REPLY`, which is only set
        by fencer peers, not clients.)

The original fencer receives all peers' `STONITH_OP_QUERY` replies via IPC
or messaging layer callback, which calls:
* `stonith_command()`, which (for replies) calls
  * `handle_reply()` which (for `STONITH_OP_QUERY`) calls
    * `process_remote_stonith_query()`, which allocates a new query result
      structure, parses device information into it, and adds it to operation
      object. It increments the number of replies received for this operation,
      and compares it against the expected number of replies (i.e. the number
      of active peers), and if this is the last expected reply, calls
      * `call_remote_stonith()`, which calculates the timeout and sends
        `STONITH_OP_FENCE` request(s) to carry out the fencing. If the target
	node has a fencing "topology" (which allows specifications such as
	"this node can be fenced either with device A, or devices B and C in
	combination"), it will choose the device(s), and send out as many
	requests as needed. If it chooses a device, it will choose the peer; a
	peer is preferred if it has "verified" access to the desired device,
	meaning that it has the device "running" on it and thus has a monitor
        operation ensuring reachability.

### Fencing operations

Each `STONITH_OP_FENCE` request goes something like this as of this writing:

The chosen peer fencer receives the `STONITH_OP_FENCE` request via IPC or
messaging layer callback, which calls:
* `stonith_command()`, which (for requests) calls
  * `handle_request()`, which (for `STONITH_OP_FENCE` from a peer) calls
    * `stonith_fence()`, which calls
      * `schedule_stonith_command()` (using supplied device if
        `F_STONITH_DEVICE` was set, otherwise the highest-priority capable
	device obtained via `get_capable_devices()` with
	`stonith_fence_get_devices_cb()`), which adds the operation to the
        device's pending operations list and triggers processing.

The chosen peer fencer's mainloop is triggered and calls
* `stonith_device_dispatch()`, which calls
  * `stonith_device_execute()`, which pops off the next item from the device's
    pending operations list. If acting as the (internally implemented) watchdog
    agent, it panics the node, otherwise it calls
    * `stonith_action_create()` and `stonith_action_execute_async()` to call the fencing agent.

The chosen peer fencer's mainloop is triggered again once the fencing agent returns, and calls
* `stonith_action_async_done()` which adds the results to an action object then calls its
  * done callback (`st_child_done()`), which calls `schedule_stonith_command()`
    for a new device if there are further required actions to execute or if the
    original action failed, then builds and sends an XML reply to the original
    fencer (via `stonith_send_async_reply()`), then checks whether any
    pending actions are the same as the one just executed and merges them if so.

### Fencing replies

The original fencer receives the `STONITH_OP_FENCE` reply via IPC or
messaging layer callback, which calls:
* `stonith_command()`, which (for replies) calls
  * `handle_reply()`, which calls
    * `process_remote_stonith_exec()`, which calls either
      `call_remote_stonith()` (to retry a failed operation, or try the next
       device in a topology is appropriate, which issues a new
      `STONITH_OP_FENCE` request, proceeding as before) or `remote_op_done()`
      (if the operation is definitively failed or successful).
      * remote_op_done() broadcasts the result to all peers.

Finally, all peers receive the broadcast result and call
* `remote_op_done()`, which sends the result to all local clients.
