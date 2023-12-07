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

.. list-table:: **Required Actions for OCF Agents**
   :class: longtable
   :widths: 1 4 3
   :header-rows: 1

   * - Action
     - Description
     - Instructions
   * - .. _start_action:

       .. index::
          single: OCF resource agent; start
          single: start action

       start
     - Start the resource
     - Return :ref:`OCF_SUCCESS <OCF_SUCCESS>` on success and an appropriate
       error code otherwise. Must not report success until the resource is fully
       active.
   * - .. _stop_action:

       .. index::
          single: OCF resource agent; stop
          single: stop action

       stop
     - Stop the resource
     - Return :ref:`OCF_SUCCESS <OCF_SUCCESS>` on success and an appropriate
       error code otherwise. Must not report success until the resource is fully
       stopped.
   * - .. _monitor_action:

       .. index::
          single: OCF resource agent; monitor
          single: monitor action

       monitor
     - Check the resource's state
     - Return :ref:`OCF_SUCCESS <OCF_SUCCESS>` if the resource is running,
       :ref:`OCF_NOT_RUNNING <OCF_NOT_RUNNING>` if it is stopped, and any other
       :ref:`OCF exit code <ocf_return_codes>` if it is failed. **Note:** The
       monitor action should test the state of the resource on the local machine
       only.
   * - .. _meta_data_action:

       .. index::
          single: OCF resource agent; meta-data
          single: meta-data action

       meta-data
     - Describe the resource
     - Provide information about this resource in the XML format defined by the
       OCF standard. Return :ref:`OCF_SUCCESS <OCF_SUCCESS>`. **Note:** This is
       *not* required to be performed as root.

OCF resource agents may optionally implement additional actions. Some are used
only with advanced resource types such as clones.

.. list-table:: **Optional Actions for OCF Resource Agents**
   :class: longtable:
   :widths: 1 4 3
   :header-rows: 1

   * - Action
     - Description
     - Instructions
   * - .. _validate_all_action:

       .. index::
          single: OCF resource agent; validate-all
          single: validate-all action

       validate-all
     - Validate the instance parameters provided.
     - Return :ref:`OCF_SUCCESS <OCF_SUCCESS>` if parameters are valid,
       :ref:`OCF_ERR_ARGS <OCF_ERR_ARGS>` if not valid, and
       :ref:`OCF_ERR_CONFIGURED <OCF_ERR_CONFIGURED>` if resource is not
       configured.
   * - .. _promote_action:

       .. index::
          single: OCF resource agent; promote
          single: promote action

       promote
     - Bring the local instance of a promotable clone resource to the promoted
       role.
     - Return :ref:`OCF_SUCCESS <OCF_SUCCESS>` on success.
   * - .. _demote_action:

       .. index::
          single: OCF resource agent; demote
          single: demote action

       demote
     - Bring the local instance of a promotable clone resource to the unpromoted
       role.
     - Return :ref:`OCF_SUCCESS <OCF_SUCCESS>` on success.
   * - .. _notify_action:

       .. index::
          single: OCF resource agent; notify
          single: notify action

       notify
     - Used by the cluster to send the agent pre- and post-notification events
       telling the resource what has happened and what will happen.
     - Must not fail. Must return :ref:`OCF_SUCCESS <OCF_SUCCESS>`.
   * - .. _reload_action:

       .. index::
          single: OCF resource agent; reload
          single: reload action

       reload
     - Reload the service's own configuration.
     - Not used by Pacemaker.
   * - .. _reload_agent_action:

       .. index::
          single: OCF resource agent; reload-agent
          single: reload-agent action

       reload-agent
     - Make effective any changes in instance parameters marked as reloadable in
       the agent's meta-data.
     - This is used when the agent can handle a change in some of its parameters
       more efficiently than stopping and starting the resource.
   * - .. _recover_action:

       .. index::
          single: OCF resource agent; recover
          single: recover action

       recover
     - Restart the service.
     - Not used by Pacemaker.

.. important::

   If you create a new OCF resource agent, use `ocf-tester` to verify that the
   agent complies with the OCF standard properly.


.. index::
   single: OCF resource agent; return code

How Are OCF Return Codes Interpreted?
_____________________________________

The first thing the cluster does is to check the return code against the
expected result. If the result does not match the expected value, then the
operation is considered to have failed, and recovery action is initiated.

There are three types of failure recovery:

.. list-table:: **Types of Recovery Performed by the Cluster**
   :class: longtable
   :widths: 1 5 5
   :header-rows: 1

   * - Type
     - Description
     - Action Taken by the Cluster
   * - .. _soft_error:

       .. index::
          single: OCF resource agent; soft error

       soft
     - A transient error
     - Restart the resource or move it to a new location
   * - .. _hard_error:

       .. index::
          single: OCF resource agent; hard error

       hard
     - A non-transient error that may be specific to the current node
     - Move the resource elsewhere and prevent it from being retried on the
       current node
   * - .. _fatal_error:

       .. index::
          single: OCF resource agent; fatal error

       fatal
     - A non-transient error that will be common to all cluster nodes (for
       example, a bad configuration was specified)
     - Stop the resource and prevent it from being started on any cluster node

.. _ocf_return_codes:

OCF Return Codes
________________

The following table outlines the various OCF return codes and the type of
recovery the cluster will initiate when a failure code is received. Although
counterintuitive, even actions that return ``OCF_SUCCESS`` can be considered to
have failed, if ``OCF_SUCCESS`` was not the expected return value.

.. list-table:: **OCF Exit Codes and Their Recovery Types**
   :class: longtable
   :widths: 1 3 6 2
   :header-rows: 1

   * - Exit Code
     - OCF Alias
     - Description
     - Recovery
   * - .. _OCF_SUCCESS:

       .. index::
          single: OCF_SUCCESS
          single: OCF return code; OCF_SUCCESS
          pair: OCF return code; 0

       0
     - OCF_SUCCESS
     - Success. The command completed successfully. This is the expected result
       for all start, stop, promote, and demote actions.
     - :ref:`soft <soft_error>`
   * - .. _OCF_ERR_GENERIC:

       .. index::
          single: OCF_ERR_GENERIC
          single: OCF return code; OCF_ERR_GENERIC
          pair: OCF return code; 1

       1
     - OCF_ERR_GENERIC
     - Generic "there was a problem" error code.
     - :ref:`hard <hard_error>`
   * - .. _OCF_ERR_ARGS:

       .. index::
          single: OCF_ERR_ARGS
          single: OCF return code; OCF_ERR_ARGS
          pair: OCF return code; 2

       2
     - OCF_ERR_ARGS
     - The resource's parameter values are not valid on this machine (for
       example, a value refers to a file not found on the local host).
     - :ref:`hard <hard_error>`
   * - .. _OCF_ERR_UNIMPLEMENTED:

       .. index::
          single: OCF_ERR_UNIMPLEMENTED
          single: OCF return code; OCF_ERR_UNIMPLEMENTED
          pair: OCF return code; 3

       3
     - OCF_ERR_UNIMPLEMENTED
     - The requested action is not implemented.
     - :ref:`hard <hard_error>`
   * - .. _OCF_ERR_PERM:

       .. index::
          single: OCF_ERR_PERM
          single: OCF return code; OCF_ERR_PERM
          pair: OCF return code; 4

       4
     - OCF_ERR_PERM
     - The resource agent does not have sufficient privileges to complete the
       task.
     - :ref:`hard <hard_error>`
   * - .. _OCF_ERR_INSTALLED:

       .. index::
          single: OCF_ERR_INSTALLED
          single: OCF return code; OCF_ERR_INSTALLED
          pair: OCF return code; 5

       5
     - OCF_ERR_INSTALLED
     - The tools required by the resource are not installed on this machine.
     - :ref:`hard <hard_error>`
   * - .. _OCF_ERR_CONFIGURED:

       .. index::
          single: OCF_ERR_CONFIGURED
          single: OCF return code; OCF_ERR_CONFIGURED
          pair: OCF return code; 6

       6
     - OCF_ERR_CONFIGURED
     - The resource's parameter values are inherently invalid (for example, a
       required parameter was not given).
     - :ref:`fatal <fatal_error>`
   * - .. _OCF_NOT_RUNNING:

       .. index::
          single: OCF_NOT_RUNNING
          single: OCF return code; OCF_NOT_RUNNING
          pair: OCF return code; 7

       7
     - OCF_NOT_RUNNING
     - The resource is safely stopped. This should only be returned by monitor
       actions, not stop actions.
     - N/A
   * - .. _OCF_RUNNING_PROMOTED:

       .. index::
          single: OCF_RUNNING_PROMOTED
          single: OCF return code; OCF_RUNNING_PROMOTED
          pair: OCF return code; 8

       8
     - OCF_RUNNING_PROMOTED
     - The resource is running in the promoted role.
     - :ref:`soft <soft_error>`
   * - .. _OCF_FAILED_PROMOTED:

       .. index::
          single: OCF_FAILED_PROMOTED
          single: OCF return code; OCF_FAILED_PROMOTED
          pair: OCF return code; 9

       9
     - OCF_FAILED_PROMOTED
     - The resource is (or might be) in the promoted role but has failed. The
       resource will be demoted, stopped, and then started (and possibly
       promoted) again.
     - :ref:`soft <soft_error>`
   * - .. _OCF_DEGRADED:

       .. index::
          single: OCF_DEGRADED
          single: OCF return code; OCF_DEGRADED
          pair: OCF return code; 190

       190
     - OCF_DEGRADED
     - The resource is properly active, but in such a condition that future
       failures are more likely.
     - none
   * - .. _OCF_DEGRADED_PROMOTED:

       .. index::
          single: OCF_DEGRADED_PROMOTED
          single: OCF return code; OCF_DEGRADED_PROMOTED
          pair: OCF return code; 191

       191
     - OCF_DEGRADED_PROMOTED
     - The resource is properly active in the promoted role, but in such a
       condition that future failures are more likely.
     - none
   * - other
     - *none*
     - Custom error code.
     - soft

Exceptions to the recovery handling described above:

* Probes (non-recurring monitor actions) that find a resource active
  (or in the promoted role) will not result in recovery action unless it is
  also found active elsewhere.
* The recovery action taken when a resource is found active more than
  once is determined by the resource's ``multiple-active`` property.
* Recurring actions that return ``OCF_ERR_UNIMPLEMENTED``
  do not cause any type of recovery.
* Actions that return one of the "degraded" codes will be treated the same as
  if they had returned success, but status output will indicate that the
  resource is degraded.

Clone Resource Agent Requirements
_________________________________

Any resource can be used as an anonymous clone, as it requires no additional
support from the resource agent. Whether it makes sense to do so depends on your
resource and its resource agent.

Resource Agent Requirements for Globally Unique Clones
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Globally unique clones require additional support in the resource agent. In
particular, it must respond with ``OCF_SUCCESS`` only if the node has that exact
instance active. All other probes for instances of the clone should result in
``OCF_NOT_RUNNING`` (or one of the other OCF error codes if they are failed).

Individual instances of a clone are identified by appending a colon and a
numerical offset (for example, ``apache:2``).

A resource agent can find out how many copies there are by examining the
``OCF_RESKEY_CRM_meta_clone_max`` environment variable and which instance it is
by examining ``OCF_RESKEY_CRM_meta_clone``.

The resource agent must not make any assumptions (based on
``OCF_RESKEY_CRM_meta_clone``) about which numerical instances are active. In
particular, the list of active copies is not always an unbroken sequence, nor
does it always start at 0.

Resource Agent Requirements for Promotable Clones
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Promotable clone resources require two extra actions, ``demote`` and ``promote``,
which are responsible for changing the state of the resource. Like ``start`` and
``stop``, they should return ``OCF_SUCCESS`` if they completed successfully or a
relevant error code if they did not.

The states can mean whatever you wish, but when the resource is started, it must
begin in the unpromoted role. From there, the cluster will decide which
instances to promote.

In addition to the clone requirements for monitor actions, agents must also
*accurately* report which state they are in. The cluster relies on the agent to
report its status (including role) accurately and does not indicate to the agent
what role it currently believes it to be in.

.. list-table:: **Role Implications of OCF Return Codes**
   :class: longtable
   :widths: 1 3
   :header-rows: 1

   * - Monitor Return Code
     - Description
   * - :ref:`OCF_NOT_RUNNING <OCF_NOT_RUNNING>`
     - .. index::
          single: OCF_NOT_RUNNING
          single: OCF return code; OCF_NOT_RUNNING

       Stopped
   * - :ref:`OCF_SUCCESS <OCF_SUCCESS>`
     - .. index::
          single: OCF_SUCCESS
          single: OCF return code; OCF_SUCCESS

       Running (Unpromoted)
   * - :ref:`OCF_RUNNING_PROMOTED <OCF_RUNNING_PROMOTED>`
     - .. index::
          single: OCF_RUNNING_PROMOTED
          single: OCF return code; OCF_RUNNING_PROMOTED

       Running (Promoted)
   * - :ref:`OCF_FAILED_PROMOTED <OCF_FAILED_PROMOTED>`
     - .. index::
          single: OCF_FAILED_PROMOTED
          single: OCF return code; OCF_FAILED_PROMOTED

       Failed (Promoted)
   * - Other
     - Failed (Unpromoted)

Clone Notifications
~~~~~~~~~~~~~~~~~~~

If the clone has the ``notify`` meta-attribute set to ``true`` and the resource
agent supports the ``notify`` action, Pacemaker will call the action when
appropriate, passing a number of extra variables. These variables, when combined
with additional context, can be used to calculate the current state of the
cluster and what is about to happen to it.

.. index::
   single: clone; environment variables
   single: notify; environment variables

.. list-table:: **Environment Variables Supplied with Clone Notify Actions**
   :class: longtable
   :widths: 1 1
   :header-rows: 1

   * - Variable
     - Description
   * - .. _OCF_RESKEY_CRM_meta_notify_type:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_type
          single: OCF_RESKEY_CRM_meta_notify_type

       OCF_RESKEY_CRM_meta_notify_type
     - Allowed values: ``pre``, ``post``
   * - .. _OCF_RESKEY_CRM_meta_notify_operation:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_operation
          single: OCF_RESKEY_CRM_meta_notify_operation

       OCF_RESKEY_CRM_meta_notify_operation
     - Allowed values: ``start``, ``stop``
   * - .. _OCF_RESKEY_CRM_meta_notify_start_resource:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_start_resource
          single: OCF_RESKEY_CRM_meta_notify_start_resource

       OCF_RESKEY_CRM_meta_notify_start_resource
     - Resources to be started
   * - .. _OCF_RESKEY_CRM_meta_notify_stop_resource:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_stop_resource
          single: OCF_RESKEY_CRM_meta_notify_stop_resource

       OCF_RESKEY_CRM_meta_notify_stop_resource
     - Resources to be stopped
   * - .. _OCF_RESKEY_CRM_meta_notify_active_resource:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_active_resource
          single: OCF_RESKEY_CRM_meta_notify_active_resource

       OCF_RESKEY_CRM_meta_notify_active_resource
     - Resources that are running
   * - .. _OCF_RESKEY_CRM_meta_notify_inactive_resource:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_inactive_resource
          single: OCF_RESKEY_CRM_meta_notify_inactive_resource

       OCF_RESKEY_CRM_meta_notify_inactive_resource
     - Resources that are not running
   * - .. _OCF_RESKEY_CRM_meta_notify_start_uname:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_start_uname
          single: OCF_RESKEY_CRM_meta_notify_start_uname

       OCF_RESKEY_CRM_meta_notify_start_uname
     - Nodes on which resources will be started
   * - .. _OCF_RESKEY_CRM_meta_notify_stop_uname:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_stop_uname
          single: OCF_RESKEY_CRM_meta_notify_stop_uname

       OCF_RESKEY_CRM_meta_notify_stop_uname
     - Nodes on which resources will be stopped
   * - .. _OCF_RESKEY_CRM_meta_notify_active_uname:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_active_uname
          single: OCF_RESKEY_CRM_meta_notify_active_uname

       OCF_RESKEY_CRM_meta_notify_active_uname
     - Nodes on which resources are running

The variables come in pairs, such as
``OCF_RESKEY_CRM_meta_notify_start_resource`` and
``OCF_RESKEY_CRM_meta_notify_start_uname``, and should be treated as an array of
whitespace-separated elements.

``OCF_RESKEY_CRM_meta_notify_inactive_resource`` is an exception, as the
matching ``uname`` variable does not exist since inactive resources are not
running on any node.

Thus, in order to indicate that ``clone:0`` will be started on ``sles-1``,
``clone:2`` will be started on ``sles-3``, and ``clone:3`` will be started
on ``sles-2``, the cluster would set:

.. topic:: Notification Variables

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

.. list-table:: **Extra Environment Variables Supplied for Promotable Clones**
   :class: longtable
   :widths: 1 1
   :header-rows: 1

   * - Variable
     - Description
   * - .. _OCF_RESKEY_CRM_meta_notify_promoted_resource:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_promoted_resource
          single: OCF_RESKEY_CRM_meta_notify_promoted_resource

       OCF_RESKEY_CRM_meta_notify_promoted_resource
     - Resources that are running in the promoted role
   * - .. _OCF_RESKEY_CRM_meta_notify_unpromoted_resource:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_unpromoted_resource
          single: OCF_RESKEY_CRM_meta_notify_unpromoted_resource

       OCF_RESKEY_CRM_meta_notify_unpromoted_resource
     - Resources that are running in the unpromoted role
   * - .. _OCF_RESKEY_CRM_meta_notify_promote_resource:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_promote_resource
          single: OCF_RESKEY_CRM_meta_notify_promote_resource

       OCF_RESKEY_CRM_meta_notify_promote_resource
     - Resources to be promoted
   * - .. _OCF_RESKEY_CRM_meta_notify_demote_resource:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_demote_resource
          single: OCF_RESKEY_CRM_meta_notify_demote_resource

       OCF_RESKEY_CRM_meta_notify_demote_resource
     - Resources to be demoted
   * - .. _OCF_RESKEY_CRM_meta_notify_promote_uname:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_promote_uname
          single: OCF_RESKEY_CRM_meta_notify_promote_uname

       OCF_RESKEY_CRM_meta_notify_promote_uname
     - Nodes on which resources will be promoted
   * - .. _OCF_RESKEY_CRM_meta_notify_demote_uname:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_demote_uname
          single: OCF_RESKEY_CRM_meta_notify_demote_uname

       OCF_RESKEY_CRM_meta_notify_demote_uname
     - Nodes on which resources will be demoted
   * - .. _OCF_RESKEY_CRM_meta_notify_promoted_uname:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_promoted_uname
          single: OCF_RESKEY_CRM_meta_notify_promoted_uname

       OCF_RESKEY_CRM_meta_notify_promoted_uname
     - Nodes on which resources are running in the promoted role
   * - .. _OCF_RESKEY_CRM_meta_notify_unpromoted_uname:

       .. index::
          single: environment variable; OCF_RESKEY_CRM_meta_notify_unpromoted_uname
          single: OCF_RESKEY_CRM_meta_notify_unpromoted_uname

       OCF_RESKEY_CRM_meta_notify_unpromoted_uname
     - Nodes on which resources are running in the unpromoted role

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
