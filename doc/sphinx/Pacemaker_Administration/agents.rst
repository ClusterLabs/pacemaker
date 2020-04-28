Resource Agents
---------------

Resource Agent Actions
######################

If one resource depends on another resource via constraints, the cluster will
interpret an expected result as sufficient to continue with dependent actions.
This may cause timing issues if the resource agent start returns before the
service is not only launched but fully ready to perform its function, or if the
resource agent stop returns before the service has fully released all its
claims on system resources. At a minimum, the start or stop should not return
before a status command would return the expected (started or stopped) result.

OCF Resource Agents
###################

Location of Custom Scripts
__________________________

.. index:: OCF resource agents

OCF Resource Agents are found in ``/usr/lib/ocf/resource.d/$PROVIDER``

When creating your own agents, you are encouraged to create a new directory
under ``/usr/lib/ocf/resource.d/`` so that they are not confused with (or
overwritten by) the agents shipped by existing providers.

So, for example, if you choose the provider name of big-corp and want a new
resource named big-app, you would create a resource agent called
``/usr/lib/ocf/resource.d/big-corp/big-app`` and define a resource:
 
.. code-block: xml

   <primitive id="custom-app" class="ocf" provider="big-corp" type="big-app"/>

Actions
_______

All OCF resource agents are required to implement the following actions.

.. table:: Required Actions for OCF Agents

+--------------+-------------+------------------------------------------------+
| Action       | Description | Instructions                                   |
+==============+=============+================================================+
| start        | Start the   | Return 0 on success and an appropriate         |
|              | resource    | error code otherwise. Must not report          |
|              |             | success until the resource is fully            |
|              |             | active.                                        |
|              |             |                                                |
|              |             | .. index::                                     |
|              |             |    pair: start; OCF action                     |
|              |             |    pair: start; action                         |
+--------------+-------------+------------------------------------------------+
| stop         | Stop the    | Return 0 on success and an appropriate         |
|              | resource    | error code otherwise. Must not report          |
|              |             | success until the resource is fully            |
|              |             | stopped.                                       |
|              |             |                                                |
|              |             | .. index::                                     |
|              |             |    pair: stop; OCF action                      |
|              |             |    pair: stop; action                          |
+--------------+-------------+------------------------------------------------+
| monitor      | Check the   | Exit 0 if the resource is running, 7           |
|              | resource's  | if it is stopped, and any other OCF            |
|              | state       | exit code if it is failed. NOTE: The           |
|              |             | monitor script should test the state           |
|              |             | of the resource on the local machine           |
|              |             | only.                                          |
|              |             |                                                |
|              |             | .. index::                                     |
|              |             |    pair: monitor; OCF action                   |
|              |             |    pair: monitor; action                       |
+--------------+-------------+------------------------------------------------+
| meta-data    | Describe    | Provide information about this                 |
|              | the         | resource in the XML format defined by          |
|              | resource    | the OCF standard. Exit with 0. NOTE:           |
|              |             | This is *not* required to be performed         |
|              |             | as root.                                       |
|              |             |                                                |
|              |             | .. index::                                     |
|              |             |    pair: meta-data; OCF action                 |
|              |             |    pair: meta-data; action                     |
+--------------+-------------+------------------------------------------------+
| validate-all | Verify the  | Return 0 if parameters are valid, 2 if         |
|              | supplied    | not valid, and 6 if resource is not            |
|              | parameters  | configured.                                    |
|              |             |                                                |
|              |             | .. index::                                     |
|              |             |    pair: validate-all; OCF action              |
|              |             |    pair: validate-all; action                  |
+--------------+-------------+------------------------------------------------+

Additional requirements (not part of the OCF specification) are placed on
agents that will be used for advanced concepts such as clone resources.

.. table:: Optional Actions for OCF Resource Agents

+--------------+-------------+------------------------------------------------+
| Action       | Description | Instructions                                   |
+==============+=============+================================================+
| promote      | Promote the | Return 0 on success                            |
|              | local       |                                                |
|              | instance of | .. index::                                     |
|              | a promotable|    pair: promote; OCF action                   |
|              | clone       |    pair: promote; action                       |
|              | resource to |                                                |
|              | the master  |                                                |
|              | (primary)   |                                                |
|              | state.      |                                                |
+--------------+-------------+------------------------------------------------+
| demote       | Demote the  | Return 0 on success                            |
|              | local       |                                                |
|              | instance of | .. index::                                     |
|              | a promotable|    pair: demote; OCF action                    |
|              | clone       |    pair: demote; action                        |
|              | resource to |                                                |
|              | the slave   |                                                |
|              | (secondary) |                                                |
|              | state.      |                                                |
+--------------+-------------+------------------------------------------------+
| notify       | Used by the | Must not fail. Must exit with 0                |
|              | cluster to  |                                                |
|              | send        | .. index::                                     |
|              | the agent   |    pair: notify; OCF action                    |
|              | pre- and    |    pair: notify; action                        |
|              | post-       |                                                |
|              | notification|                                                |
|              | events      |                                                |
|              | telling the |                                                |
|              | resource    |                                                |
|              | what has    |                                                |
|              | happened and|                                                |
|              | will happen.|                                                |
+--------------+-------------+------------------------------------------------+

One action specified in the OCF specs, ``recover``, is not currently used by
the cluster. It is intended to be a variant of the ``start`` action that tries
to recover a resource locally.

.. important::

    If you create a new OCF resource agent, use `ocf-tester` to verify that the
    agent complies with the OCF standard properly.

.. index:: ocf-tester

How are OCF Return Codes Interpreted?
_____________________________________

The first thing the cluster does is to check the return code against
the expected result.  If the result does not match the expected value,
then the operation is considered to have failed, and recovery action is
initiated.

There are three types of failure recovery:

.. table:: Types of recovery performed by the cluster

+-------+------------------------------+--------------------------------------+
| Type  | Description                  | Action Taken by the Cluster          |
+=======+==============================+======================================+
| soft  | A transient error occurred   | Restart the resource or move it to a |
|       |                              | new location                         |
|       | .. index::                   |                                      |
|       |    pair: soft; OCF error     |                                      |
+-------+------------------------------+--------------------------------------+
| hard  | A non-transient error that   | Move the resource elsewhere and      |
|       | may be specific to the       | prevent it from being retried on the |
|       | current node                 | current node                         |
|       |                              |                                      |
|       | .. index::                   |                                      |
|       |    pair: hard; OCF error     |                                      |
+-------+------------------------------+--------------------------------------+
| fatal | A non-transient error that   | Stop the resource and prevent it     |
|       | will be common to all        | from being started on any cluster    |
|       | cluster nodes (e.g. a bad    | node                                 |
|       | configuration was specified) |                                      |
|       |                              |                                      |
|       | .. index::                   |                                      |
|       |    pair: fatal; OCF error    |                                      |
+-------+------------------------------+--------------------------------------+

.. _ocf_return_codes:

OCF Return Codes
________________

The following table outlines the different OCF return codes and the type of
recovery the cluster will initiate when a failure code is received. Although
counterintuitive, even actions that return 0 (aka. ``OCF_SUCCESS``) can be
considered to have failed, if 0 was not the expected return value.

.. table:: OCF Exit Codes and their Recovery Types

+-------+-----------------------+---------------------------------------------+----------+
| Exit  | OCF Alias             | Description                                 | Recovery |
| Code  |                       |                                             |          |
+=======+=======================+=============================================+==========+
| 0     | OCF_SUCCESS           | Success. The command completed successfully.| soft     |
|       |                       | This is the expected result for all start,  |          |
|       |                       | stop, promote and demote commands.          |          |
|       |                       |                                             |          |
|       |                       | .. index::                                  |          |
|       |                       |    pair: return code; OCF_SUCCESS           |          |
|       |                       |    pair: return code; 0                     |          |
+-------+-----------------------+---------------------------------------------+----------+
| 1     | OCF_ERR_GENERIC       | Generic "there was a problem"               | soft     |
|       |                       | error code.                                 |          |
|       |                       |                                             |          |
|       |                       | .. index::                                  |          |
|       |                       |    pair: return code; OCF_ERR_GENERIC       |          |
|       |                       |    pair: return code; 1                     |          |
+-------+-----------------------+---------------------------------------------+----------+
| 2     | OCF_ERR_ARGS          | The resource's configuration is not valid on| hard     |
|       |                       | this machine. E.g. it refers to a location  |          |
|       |                       | not found on the node.                      |          |
|       |                       |                                             |          |
|       |                       | .. index::                                  |          |
|       |                       |     pair: return code; OCF_ERR_ARGS         |          |
|       |                       |     pair: return code; 2                    |          |
+-------+-----------------------+---------------------------------------------+----------+
| 3     | OCF_ERR_UNIMPLEMENTED | The requested action is not                 | hard     |
|       |                       | implemented.                                |          |
|       |                       |                                             |          |
|       |                       | .. index::                                  |          |
|       |                       |    pair: return code; OCF_ERR_UNIMPLEMENTED |          |
|       |                       |    pair: return code; 3                     |          |
+-------+-----------------------+---------------------------------------------+----------+
| 4     | OCF_ERR_PERM          | The resource agent does not have            | hard     |
|       |                       | sufficient privileges to complete the task. |          |
|       |                       |                                             |          |
|       |                       | .. index::                                  |          |
|       |                       |    pair: return code; OCF_ERR_PERM          |          |
|       |                       |    pair: return code; 4                     |          |
+-------+-----------------------+---------------------------------------------+----------+
| 5     | OCF_ERR_INSTALLED     | The tools required by the resource are      | hard     |
|       |                       | not installed on this machine.              |          |
|       |                       |                                             |          |
|       |                       | .. index::                                  |          |
|       |                       |    pair: return code; OCF_ERR_INSTALLED     |          |
|       |                       |    pair: return code; 5                     |          |
+-------+-----------------------+---------------------------------------------+----------+
| 6     | OCF_ERR_CONFIGURED    | The resource's configuration is invalid.    | fatal    |
|       |                       | E.g. required parameters are missing.       |          |
|       |                       |                                             |          |
|       |                       | .. index::                                  |          |
|       |                       |    pair: return code; OCF_ERR_CONFIGURED    |          |
|       |                       |    pair: return code; 6                     |          |
+-------+-----------------------+---------------------------------------------+----------+
| 7     | OCF_NOT_RUNNING       | The resource is safely stopped. The cluster | N/A      |
|       |                       | will not attempt to stop a resource that    |          |
|       |                       | returns this for any action.                |          |
|       |                       |                                             |          |
|       |                       | .. index::                                  |          |
|       |                       |    pair: return code; OCF_NOT_RUNNING       |          |
|       |                       |    pair: return code; 7                     |          |
+-------+-----------------------+---------------------------------------------+----------+
| 8     | OCF_RUNNING_MASTER    | The resource is running in                  | soft     |
|       |                       | master mode.                                |          |
|       |                       |                                             |          |
|       |                       | .. index::                                  |          |
|       |                       |    pair: return code; OCF_RUNNING_MASTER    |          |
|       |                       |    pair: return code; 8                     |          |
+-------+-----------------------+---------------------------------------------+----------+
| 9     | OCF_FAILED_MASTER     | The resource is in master mode but has      | soft     |
|       |                       | failed. The resource will be demoted,       |          |
|       |                       | stopped and then started (and possibly      |          |
|       |                       | promoted) again.                            |          |
|       |                       |                                             |          |
|       |                       | .. index::                                  |          |
|       |                       |    pair: return code; OCF_FAILED_MASTER     |          |
|       |                       |    pair: return code; 9                     |          |
+-------+-----------------------+---------------------------------------------+----------+
| other | *none*                | Custom error code.                          | soft     |
|       |                       |                                             |          |
|       |                       | .. index::                                  |          |
|       |                       |    pair: return code; other                 |          |
+-------+-----------------------+---------------------------------------------+----------+

Exceptions to the recovery handling described above:

* Probes (non-recurring monitor actions) that find a resource active
  (or in master mode) will not result in recovery action unless it is
  also found active elsewhere.
* The recovery action taken when a resource is found active more than
  once is determined by the resource's ``multiple-active`` property.
* Recurring actions that return ``OCF_ERR_UNIMPLEMENTED``
  do not cause any type of recovery.


LSB Resource Agents (Init Scripts)
##################################

LSB Compliance
______________

The relevant part of the
`LSB specifications <http://refspecs.linuxfoundation.org/lsb.shtml>`_
includes a description of all the return codes listed here.
    
Assuming `some_service` is configured correctly and currently
inactive, the following sequence will help you determine if it is
LSB-compatible:

#. Start (stopped):
 
   .. code-block:: none

      # /etc/init.d/some_service start ; echo "result: $?"

   * Did the service start?
   * Did the echo command print ``result: 0`` (in addition to the init script's
     usual output)?

#. Status (running):
 
   .. code-block:: none

      # /etc/init.d/some_service status ; echo "result: $?"

   * Did the script accept the command?
   * Did the script indicate the service was running?
   * Did the echo command print ``result: 0`` (in addition to the init script's
     usual output)?

#. Start (running):
 
   .. code-block:: none

      # /etc/init.d/some_service start ; echo "result: $?"

   * Is the service still running?
   * Did the echo command print ``result: 0`` (in addition to the init
      script's usual output)?

#. Stop (running):
 
   .. code-block:: none

      # /etc/init.d/some_service stop ; echo "result: $?"

   * Was the service stopped?
   * Did the echo command print ``result: 0`` (in addition to the init
     script's usual output)?

#. Status (stopped):
 
   .. code-block:: none

      # /etc/init.d/some_service status ; echo "result: $?"

   * Did the script accept the command?
   * Did the script indicate the service was not running?
   * Did the echo command print ``result: 3`` (in addition to the init
     script's usual output)?

#. Stop (stopped):
 
   .. code-block:: none

      # /etc/init.d/some_service stop ; echo "result: $?"

   * Is the service still stopped?
   * Did the echo command print ``result: 0`` (in addition to the init
     script's usual output)?

#. Status (failed):

   This step is not readily testable and relies on manual inspection of the script.

   The script can use one of the error codes (other than 3) listed in the
   LSB spec to indicate that it is active but failed. This tells the
   cluster that before moving the resource to another node, it needs to
   stop it on the existing one first.

If the answer to any of the above questions is no, then the script is not
LSB-compliant. Your options are then to either fix the script or write an OCF
agent based on the existing script.
