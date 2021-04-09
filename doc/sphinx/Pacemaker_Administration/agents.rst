.. index::
   single: resource agent

Resource Agents
---------------


Action Completion
#################

If one resource depends on another resource via constraints, the cluster will
interpret an expected result as sufficient to continue with dependent actions.
This may cause timing issues if the resource agent start returns before the
service is not only launched but fully ready to perform its function, or if the
resource agent stop returns before the service has fully released all its
claims on system resources. At a minimum, the start or stop should not return
before a status command would return the expected (started or stopped) result.


.. index::
   single: OCF resource agent
   single: resource agent; OCF

OCF Resource Agents
###################

.. index::
   single: OCF resource agent; location

Location of Custom Scripts
__________________________

OCF Resource Agents are found in ``/usr/lib/ocf/resource.d/$PROVIDER``

When creating your own agents, you are encouraged to create a new directory
under ``/usr/lib/ocf/resource.d/`` so that they are not confused with (or
overwritten by) the agents shipped by existing providers.

So, for example, if you choose the provider name of big-corp and want a new
resource named big-app, you would create a resource agent called
``/usr/lib/ocf/resource.d/big-corp/big-app`` and define a resource:
 
.. code-block: xml

   <primitive id="custom-app" class="ocf" provider="big-corp" type="big-app"/>


.. index::
   single: OCF resource agent; action

Actions
_______

All OCF resource agents are required to implement the following actions.

.. table:: **Required Actions for OCF Agents**

   +--------------+-------------+------------------------------------------------+
   | Action       | Description | Instructions                                   |
   +==============+=============+================================================+
   | start        | Start the   | .. index::                                     |
   |              | resource    |    single: OCF resource agent; start           |
   |              |             |    single: start action                        |
   |              |             |                                                |
   |              |             | Return 0 on success and an appropriate         |
   |              |             | error code otherwise. Must not report          |
   |              |             | success until the resource is fully            |
   |              |             | active.                                        |
   +--------------+-------------+------------------------------------------------+
   | stop         | Stop the    | .. index::                                     |
   |              | resource    |    single: OCF resource agent; stop            |
   |              |             |    single: stop action                         |
   |              |             |                                                |
   |              |             | Return 0 on success and an appropriate         |
   |              |             | error code otherwise. Must not report          |
   |              |             | success until the resource is fully            |
   |              |             | stopped.                                       |
   +--------------+-------------+------------------------------------------------+
   | monitor      | Check the   | .. index::                                     |
   |              | resource's  |    single: OCF resource agent; monitor         |
   |              | state       |    single: monitor action                      |
   |              |             |                                                |
   |              |             | Exit 0 if the resource is running, 7           |
   |              |             | if it is stopped, and any other OCF            |
   |              |             | exit code if it is failed. NOTE: The           |
   |              |             | monitor script should test the state           |
   |              |             | of the resource on the local machine           |
   |              |             | only.                                          |
   +--------------+-------------+------------------------------------------------+
   | meta-data    | Describe    | .. index::                                     |
   |              | the         |    single: OCF resource agent; meta-data       |
   |              | resource    |    single: meta-data action                    |
   |              |             |                                                |
   |              |             | Provide information about this                 |
   |              |             | resource in the XML format defined by          |
   |              |             | the OCF standard. Exit with 0. NOTE:           |
   |              |             | This is *not* required to be performed         |
   |              |             | as root.                                       |
   +--------------+-------------+------------------------------------------------+
   | validate-all | Verify the  | .. index::                                     |
   |              | supplied    |    single: OCF resource agent; validate-all    |
   |              | parameters  |    single: validate-all action                 |
   |              |             |                                                |
   |              |             | Return 0 if parameters are valid, 2 if         |
   |              |             | not valid, and 6 if resource is not            |
   |              |             | configured.                                    |
   +--------------+-------------+------------------------------------------------+

Additional requirements (not part of the OCF specification) are placed on
agents that will be used for advanced concepts such as clone resources.

.. table:: **Optional Actions for OCF Resource Agents**

   +--------------+-------------+------------------------------------------------+
   | Action       | Description | Instructions                                   |
   +==============+=============+================================================+
   | promote      | Bring the   | .. index::                                     |
   |              | local       |    single: OCF resource agent; promote         |
   |              | instance of |    single: promote action                      |
   |              | a promotable|                                                |
   |              | clone       | Return 0 on success                            |
   |              | resource to |                                                |
   |              | the promoted|                                                |
   |              | role.       |                                                |
   +--------------+-------------+------------------------------------------------+
   | demote       | Bring the   | .. index::                                     |
   |              | local       |    single: OCF resource agent; demote          |
   |              | instance of |    single: demote action                       |
   |              | a promotable|                                                |
   |              | clone       | Return 0 on success                            |
   |              | resource to |                                                |
   |              | the         |                                                |
   |              | unpromoted  |                                                |
   |              | role.       |                                                |
   +--------------+-------------+------------------------------------------------+
   | notify       | Used by the | .. index::                                     |
   |              | cluster to  |    single: OCF resource agent; notify          |
   |              | send        |    single: notify action                       |
   |              | the agent   |                                                |
   |              | pre- and    | Must not fail. Must exit with 0                |
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


.. index::
   single: OCF resource agent; return code

How are OCF Return Codes Interpreted?
_____________________________________

The first thing the cluster does is to check the return code against
the expected result.  If the result does not match the expected value,
then the operation is considered to have failed, and recovery action is
initiated.

There are three types of failure recovery:

.. table:: **Types of recovery performed by the cluster**

   +-------+--------------------------------------------+--------------------------------------+
   | Type  | Description                                | Action Taken by the Cluster          |
   +=======+============================================+======================================+
   | soft  | .. index::                                 | Restart the resource or move it to a |
   |       |    single: OCF resource agent; soft error  | new location                         |
   |       |                                            |                                      |
   |       | A transient error occurred                 |                                      |
   +-------+--------------------------------------------+--------------------------------------+
   | hard  | .. index::                                 | Move the resource elsewhere and      |
   |       |    single: OCF resource agent; hard error  | prevent it from being retried on the |
   |       |                                            | current node                         |
   |       | A non-transient error that                 |                                      |
   |       | may be specific to the                     |                                      |
   |       | current node                               |                                      |
   +-------+--------------------------------------------+--------------------------------------+
   | fatal | .. index::                                 | Stop the resource and prevent it     |
   |       |    single: OCF resource agent; fatal error | from being started on any cluster    |
   |       |                                            | node                                 |
   |       | A non-transient error that                 |                                      |
   |       | will be common to all                      |                                      |
   |       | cluster nodes (e.g. a bad                  |                                      |
   |       | configuration was specified)               |                                      |
   +-------+--------------------------------------------+--------------------------------------+

.. _ocf_return_codes:

OCF Return Codes
________________

The following table outlines the different OCF return codes and the type of
recovery the cluster will initiate when a failure code is received. Although
counterintuitive, even actions that return 0 (aka. ``OCF_SUCCESS``) can be
considered to have failed, if 0 was not the expected return value.

.. table:: **OCF Exit Codes and their Recovery Types**

   +-------+-----------------------+---------------------------------------------------+----------+
   | Exit  | OCF Alias             | Description                                       | Recovery |
   | Code  |                       |                                                   |          |
   +=======+=======================+===================================================+==========+
   | 0     | OCF_SUCCESS           | .. index::                                        | soft     |
   |       |                       |    single: OCF_SUCCESS                            |          |
   |       |                       |    single: OCF return code; OCF_SUCCESS           |          |
   |       |                       |    pair: OCF return code; 0                       |          |
   |       |                       |                                                   |          |
   |       |                       | Success. The command completed successfully.      |          |
   |       |                       | This is the expected result for all start,        |          |
   |       |                       | stop, promote and demote commands.                |          |
   +-------+-----------------------+---------------------------------------------------+----------+
   | 1     | OCF_ERR_GENERIC       | .. index::                                        | soft     |
   |       |                       |    single: OCF_ERR_GENERIC                        |          |
   |       |                       |    single: OCF return code; OCF_ERR_GENERIC       |          |
   |       |                       |    pair: OCF return code; 1                       |          |
   |       |                       |                                                   |          |
   |       |                       | Generic "there was a problem" error code.         |          |
   +-------+-----------------------+---------------------------------------------------+----------+
   | 2     | OCF_ERR_ARGS          | .. index::                                        | hard     |
   |       |                       |     single: OCF_ERR_ARGS                          |          |
   |       |                       |     single: OCF return code; OCF_ERR_ARGS         |          |
   |       |                       |     pair: OCF return code; 2                      |          |
   |       |                       |                                                   |          |
   |       |                       | The resource's configuration is not valid on      |          |
   |       |                       | this machine. E.g. it refers to a location        |          |
   |       |                       | not found on the node.                            |          |
   +-------+-----------------------+---------------------------------------------------+----------+
   | 3     | OCF_ERR_UNIMPLEMENTED | .. index::                                        | hard     |
   |       |                       |    single: OCF_ERR_UNIMPLEMENTED                  |          |
   |       |                       |    single: OCF return code; OCF_ERR_UNIMPLEMENTED |          |
   |       |                       |    pair: OCF return code; 3                       |          |
   |       |                       |                                                   |          |
   |       |                       | The requested action is not implemented.          |          |
   +-------+-----------------------+---------------------------------------------------+----------+
   | 4     | OCF_ERR_PERM          | .. index::                                        | hard     |
   |       |                       |    single: OCF_ERR_PERM                           |          |
   |       |                       |    single: OCF return code; OCF_ERR_PERM          |          |
   |       |                       |    pair: OCF return code; 4                       |          |
   |       |                       |                                                   |          |
   |       |                       | The resource agent does not have                  |          |
   |       |                       | sufficient privileges to complete the task.       |          |
   +-------+-----------------------+---------------------------------------------------+----------+
   | 5     | OCF_ERR_INSTALLED     | .. index::                                        | hard     |
   |       |                       |    single: OCF_ERR_INSTALLED                      |          |
   |       |                       |    single: OCF return code; OCF_ERR_INSTALLED     |          |
   |       |                       |    pair: OCF return code; 5                       |          |
   |       |                       |                                                   |          |
   |       |                       | The tools required by the resource are            |          |
   |       |                       | not installed on this machine.                    |          |
   +-------+-----------------------+---------------------------------------------------+----------+
   | 6     | OCF_ERR_CONFIGURED    | .. index::                                        | fatal    |
   |       |                       |    single: OCF_ERR_CONFIGURED                     |          |
   |       |                       |    single: OCF return code; OCF_ERR_CONFIGURED    |          |
   |       |                       |    pair: OCF return code; 6                       |          |
   |       |                       |                                                   |          |
   |       |                       | The resource's configuration is invalid.          |          |
   |       |                       | E.g. required parameters are missing.             |          |
   +-------+-----------------------+---------------------------------------------------+----------+
   | 7     | OCF_NOT_RUNNING       | .. index::                                        | N/A      |
   |       |                       |    single: OCF_NOT_RUNNING                        |          |
   |       |                       |    single: OCF return code; OCF_NOT_RUNNING       |          |
   |       |                       |    pair: OCF return code; 7                       |          |
   |       |                       |                                                   |          |
   |       |                       | The resource is safely stopped. The cluster       |          |
   |       |                       | will not attempt to stop a resource that          |          |
   |       |                       | returns this for any action.                      |          |
   +-------+-----------------------+---------------------------------------------------+----------+
   | 8     | OCF_RUNNING_PROMOTED  | .. index::                                        | soft     |
   |       |                       |    single: OCF_RUNNING_PROMOTED                   |          |
   |       |                       |    single: OCF return code; OCF_RUNNING_PROMOTED  |          |
   |       |                       |    pair: OCF return code; 8                       |          |
   |       |                       |                                                   |          |
   |       |                       | The resource is running in the promoted role.     |          |
   +-------+-----------------------+---------------------------------------------------+----------+
   | 9     | OCF_FAILED_PROMOTED   | .. index::                                        | soft     |
   |       |                       |    single: OCF_FAILED_PROMOTED                    |          |
   |       |                       |    single: OCF return code; OCF_FAILED_PROMOTED   |          |
   |       |                       |    pair: OCF return code; 9                       |          |
   |       |                       |                                                   |          |
   |       |                       | The resource is (or might be) in the promoted     |          |
   |       |                       | role but has failed. The resource will be         |          |
   |       |                       | demoted, stopped and then started (and possibly   |          |
   |       |                       | promoted) again.                                  |          |
   +-------+-----------------------+---------------------------------------------------+----------+
   | other | *none*                | Custom error code.                                | soft     |
   +-------+-----------------------+---------------------------------------------------+----------+

Exceptions to the recovery handling described above:

* Probes (non-recurring monitor actions) that find a resource active
  (or in the promoted role) will not result in recovery action unless it is
  also found active elsewhere.
* The recovery action taken when a resource is found active more than
  once is determined by the resource's ``multiple-active`` property.
* Recurring actions that return ``OCF_ERR_UNIMPLEMENTED``
  do not cause any type of recovery.


.. index::
   single: resource agent; LSB
   single: LSB resource agent
   single: init script

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
