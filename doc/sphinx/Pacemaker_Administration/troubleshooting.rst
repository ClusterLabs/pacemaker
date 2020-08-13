.. index:: troubleshooting

Troubleshooting Cluster Problems
--------------------------------

.. index:: logging, pacemaker.log

Logging
#######

Pacemaker by default logs messages of notice severity and higher to the system
log, and messages of info severity and higher to the detail log, which by
default is ``/var/log/pacemaker/pacemaker.log``.

Logging options can be controlled via environment variables at Pacemaker
start-up. Where these are set varies by operating system (often
``/etc/sysconfig/pacemaker`` or ``/etc/default/pacemaker``).

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

Each transition can be identified in the logs by a line like:

.. code-block: none

   notice: Calculated transition 19, saving inputs in /var/lib/pacemaker/pengine/pe-input-1463.bz2

The file listed as the "inputs" is a snapshot of the cluster configuration and
state at that moment (the CIB). This file can help determine why particular
actions were scheduled. The ``crm_simulate`` command, described in
:ref:`crm_simulate`, can be used to replay the file.

Further Information About Troubleshooting
#########################################

Andrew Beekhof wrote a series of articles about troubleshooting in his blog,
`The Cluster Guy <http://blog.clusterlabs.org/>`_:

* `Debugging Pacemaker <http://blog.clusterlabs.org/blog/2013/debugging-pacemaker>`_
* `Debugging the Policy Engine <http://blog.clusterlabs.org/blog/2013/debugging-pengine>`_
* `Pacemaker Logging <http://blog.clusterlabs.org/blog/2013/pacemaker-logging>`_

The articles were written for an earlier version of Pacemaker, so many of the
specific names and log messages to look for have changed, but the concepts are
still valid.
