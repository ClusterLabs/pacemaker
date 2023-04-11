.. index:: troubleshooting

Troubleshooting Cluster Problems
--------------------------------

.. index:: logging, pacemaker.log

Logging
#######

Pacemaker by default logs messages of ``notice`` severity and higher to the
system log, and messages of ``info`` severity and higher to the detail log,
which by default is ``/var/log/pacemaker/pacemaker.log``.

Logging options can be controlled via environment variables at Pacemaker
start-up. Where these are set varies by operating system (often
``/etc/sysconfig/pacemaker`` or ``/etc/default/pacemaker``). See the comments
in that file for details.

Because cluster problems are often highly complex, involving multiple machines,
cluster daemons, and managed services, Pacemaker logs rather verbosely to
provide as much context as possible. It is an ongoing priority to make these
logs more user-friendly, but by necessity there is a lot of obscure, low-level
information that can make them difficult to follow.

The default log rotation configuration shipped with Pacemaker (typically
installed in ``/etc/logrotate.d/pacemaker``) rotates the log when it reaches
100MB in size, or weekly, whichever comes first.

If you configure debug or (Heaven forbid) trace-level logging, the logs can
grow enormous quite quickly. Because rotated logs are by default named with the
year, month, and day only, this can cause name collisions if your logs exceed
100MB in a single day. You can add ``dateformat -%Y%m%d-%H`` to the rotation
configuration to avoid this.

Reading the Logs
################

When troubleshooting, first check the system log or journal for errors or
warnings from Pacemaker components (conveniently, they will all have
"pacemaker" in their logged process name). For example:

.. code-block:: none

   # grep 'pacemaker.*\(error\|warning\)' /var/log/messages
   Mar 29 14:04:19 node1 pacemaker-controld[86636]: error: Result of monitor operation for rn2 on node1: Timed Out after 45s (Remote executor did not respond)

If that doesn't give sufficient information, next look at the ``notice`` level
messages from ``pacemaker-controld``. These will show changes in the state of
cluster nodes. On the DC, this will also show resource actions attempted. For
example:

.. code-block:: none

   # grep 'pacemaker-controld.*notice:' /var/log/messages
   ... output skipped for brevity ...
   Mar 29 14:05:36 node1 pacemaker-controld[86636]: notice: Node rn2 state is now lost
   ... more output skipped for brevity ...
   Mar 29 14:12:17 node1 pacemaker-controld[86636]: notice: Initiating stop operation rsc1_stop_0 on node4
   ... more output skipped for brevity ...

Of course, you can use other tools besides ``grep`` to search the logs.


.. index:: transition

Transitions
###########

A key concept in understanding how a Pacemaker cluster functions is a
*transition*. A transition is a set of actions that need to be taken to bring
the cluster from its current state to the desired state (as expressed by the
configuration).

Whenever a relevant event happens (a node joining or leaving the cluster,
a resource failing, etc.), the controller will ask the scheduler to recalculate
the status of the cluster, which generates a new transition. The controller
then performs the actions in the transition in the proper order.

Each transition can be identified in the DC's logs by a line like:

.. code-block:: none

   notice: Calculated transition 19, saving inputs in /var/lib/pacemaker/pengine/pe-input-1463.bz2

The file listed as the "inputs" is a snapshot of the cluster configuration and
state at that moment (the CIB). This file can help determine why particular
actions were scheduled. The ``crm_simulate`` command, described in
:ref:`crm_simulate`, can be used to replay the file.

The log messages immediately before the "saving inputs" message will include
any actions that the scheduler thinks need to be done.


Node Failures
#############

When a node fails, and looking at errors and warnings doesn't give an obvious
explanation, try to answer questions like the following based on log messages:

* When and what was the last successful message on the node itself, or about
  that node in the other nodes' logs?
* Did pacemaker-controld on the other nodes notice the node leave?
* Did pacemaker-controld on the DC invoke the scheduler and schedule a new
  transition?
* Did the transition include fencing the failed node?
* Was fencing attempted?
* Did fencing succeed?

Resource Failures
#################

When a resource fails, and looking at errors and warnings doesn't give an
obvious explanation, try to answer questions like the following based on log
messages:

* Did pacemaker-controld record the result of the failed resource action?
* What was the failed action's execution status and exit status?
* What code in the resource agent could result in those status codes?
* Did pacemaker-controld on the DC invoke the scheduler and schedule a new
  transition?
* Did the new transition include recovery of the resource?
* Were the recovery actions initiated, and what were their results?
