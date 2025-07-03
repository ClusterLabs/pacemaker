.. index::
   single: alert; agents

Alert Agents
------------

.. index::
   single: alert; sample agents

Using the Sample Alert Agents
#############################

Pacemaker provides several sample alert agents, installed in
``/usr/share/pacemaker/alerts`` by default.

While these sample scripts may be copied and used as-is, they are provided
mainly as templates to be edited to suit your purposes. See their source code
for the full set of instance attributes they support.

.. topic:: Sending cluster events as SNMP v2c traps

   .. code-block:: xml

      <configuration>
         <alerts>
            <alert id="snmp_alert" path="/path/to/alert_snmp.sh">
               <instance_attributes id="config_for_alert_snmp">
                  <nvpair id="trap_node_states" name="trap_node_states"
                          value="all"/>
               </instance_attributes>
               <meta_attributes id="config_for_timestamp">
                  <nvpair id="ts_fmt" name="timestamp-format"
                          value="%Y-%m-%d,%H:%M:%S.%01N"/>
               </meta_attributes>
               <recipient id="snmp_destination" value="192.168.1.2"/>
            </alert>
         </alerts>
      </configuration>

.. note:: **SNMP alert agent attributes**

   The ``timestamp-format`` meta-attribute should always be set to
   ``%Y-%m-%d,%H:%M:%S.%01N`` when using the SNMP agent, to match the SNMP
   standard.

   The SNMP agent provides a number of instance attributes in addition to the
   one used in the example above. The most useful are ``trap_version``, which
   defaults to ``2c``, and ``trap_community``, which defaults to ``public``.
   See the source code for more details.

.. topic:: Sending cluster events as SNMP v3 traps

   .. code-block:: xml

      <configuration>
         <alerts>
            <alert id="snmp_alert" path="/path/to/alert_snmp.sh">
               <instance_attributes id="config_for_alert_snmp">
                  <nvpair id="trap_node_states" name="trap_node_states"
                          value="all"/>
                  <nvpair id="trap_version" name="trap_version" value="3"/>
                  <nvpair id="trap_community" name="trap_community" value=""/>
                  <nvpair id="trap_options" name="trap_options"
                          value="-l authNoPriv -a MD5 -u testuser -A secret1"/>
               </instance_attributes>
               <meta_attributes id="config_for_timestamp">
                  <nvpair id="ts_fmt" name="timestamp-format"
                          value="%Y-%m-%d,%H:%M:%S.%01N"/>
               </meta_attributes>
               <recipient id="snmp_destination" value="192.168.1.2"/>
            </alert>
         </alerts>
      </configuration>

.. note:: **SNMP v3 trap configuration**

   To use SNMP v3, ``trap_version`` must be set to ``3``. ``trap_community``
   will be ignored.

   The example above uses the ``trap_options`` instance attribute to override
   the security level, authentication protocol, authentication user, and
   authentication password from snmp.conf. These will be passed to the snmptrap
   command. Passing the password on the command line is considered insecure;
   specify authentication and privacy options suitable for your environment.

.. topic:: Sending cluster events as e-mails

   .. code-block:: xml

      <configuration>
         <alerts>
            <alert id="smtp_alert" path="/path/to/alert_smtp.sh">
               <instance_attributes id="config_for_alert_smtp">
                  <nvpair id="email_sender" name="email_sender"
                          value="donotreply@example.com"/>
               </instance_attributes>
               <recipient id="smtp_destination" value="admin@example.com"/>
            </alert>
         </alerts>
      </configuration>


.. index::
   single: alert; agent development

Writing an Alert Agent
######################

.. index::
   single: alert; environment variables
   single: environment variable; alert agents

.. list-table:: **Environment Variables Passed to Alert Agents**
   :class: longtable
   :widths: 30 50 20
   :header-rows: 1

   * - Environment Variable
     - Description
     - Alert Types
   * - .. _CRM_alert_kind:

       .. index::
          single: environment variable; CRM_alert_kind
          single: CRM_alert_kind

       CRM_alert_kind
     - The type of alert (``node``, ``fencing``, ``resource``, or
       ``attribute``)
     - all
   * - .. _CRM_alert_node:

       .. index::
          single: environment variable; CRM_alert_node
          single: CRM_alert_node

       CRM_alert_node
     - Name of affected node
     - all
   * - .. _CRM_alert_node_sequence:

       .. index::
          single: environment variable; CRM_alert_node_sequence
          single: CRM_alert_node_sequence

       CRM_alert_node_sequence
     - A sequence number increased whenever an alert is being issued on the
       local node, which can be used to reference the order in which alerts
       have been issued by Pacemaker. An alert for an event that happened later
       in time reliably has a higher sequence number than alerts for earlier
       events. This number has no cluster-wide meaning.
     - all
   * - .. _CRM_alert_recipient:

       .. index::
          single: environment variable; CRM_alert_recipient
          single: CRM_alert_recipient

       CRM_alert_recipient
     - The configured recipient
     - all
   * - .. _CRM_alert_timestamp:

       .. index::
          single: environment variable; CRM_alert_timestamp
          single: CRM_alert_timestamp

       CRM_alert_timestamp
     - A timestamp created prior to executing the agent, in the format
       specified by the ``timestamp-format`` meta-attribute.  This allows the
       agent to have a reliable, high-precision time of when the event
       occurred, regardless of when the agent itself was invoked (which could
       potentially be delayed due to system load, etc.).
     - all
   * - .. _CRM_alert_timestamp_epoch:

       .. index::
          single: environment variable; CRM_alert_timestamp_epoch
          single: CRM_alert_timestamp_epoch

       CRM_alert_timestamp_epoch
     - The same time as ``CRM_alert_timestamp``, expressed as the integer
       number of seconds since January 1, 1970. This (along with
       ``CRM_alert_timestamp_usec``) can be useful for alert agents that need
       to format time in a specific way rather than let the user configure it.
     - all
   * - .. _CRM_alert_timestamp_usec:

       .. index::
          single: environment variable; CRM_alert_timestamp_usec
          single: CRM_alert_timestamp_usec

       CRM_alert_timestamp_usec
     - The same time as ``CRM_alert_timestamp``, expressed as the integer
       number of microseconds since ``CRM_alert_timestamp_epoch``.
     - all
   * - .. _CRM_alert_version:

       .. index::
          single: environment variable; CRM_alert_version
          single: CRM_alert_version

       CRM_alert_version
     - The version of Pacemaker sending the alert
     - all
   * - .. _CRM_alert_desc:

       .. index::
          single: environment variable; CRM_alert_desc
          single: CRM_alert_desc

       CRM_alert_desc
     - Detail about event. For ``node`` alerts, this is the node's current
       state (``member`` or ``lost``). For ``fencing`` alerts, this is a
       summary of the requested fencing operation, including origin, target,
       and fencing operation error code, if any. For ``resource`` alerts, this
       is a readable string equivalent of ``CRM_alert_status``.
     - ``node``, ``fencing``, ``resource``
   * - .. _CRM_alert_nodeid:

       .. index::
          single: environment variable; CRM_alert_nodeid
          single: CRM_alert_nodeid

       CRM_alert_nodeid
     - ID of node whose status changed
     - ``node``
   * - .. _CRM_alert_rc:

       .. index::
          single: environment variable; CRM_alert_rc
          single: CRM_alert_rc

       CRM_alert_rc
     - The numerical return code of the fencing or resource operation
     - ``fencing``, ``resource``
   * - .. _CRM_alert_task:

       .. index::
          single: environment variable; CRM_alert_task
          single: CRM_alert_task

       CRM_alert_task
     - The requested fencing or resource operation
     - ``fencing``, ``resource``
   * - .. _CRM_alert_exec_time:

       .. index::
          single: environment variable; CRM_alert_exec_time
          single: CRM_alert_exec_time

       CRM_alert_exec_time
     - The (wall-clock) time, in milliseconds, that it took to execute the
       action. If the action timed out, ``CRM_alert_status`` will be 2,
       ``CRM_alert_desc`` will be "Timed Out", and this value will be the
       action timeout. May not be supported on all platforms. *(since 2.0.1)*
     - ``resource``
   * - .. _CRM_alert_interval:

       .. index::
          single: environment variable; CRM_alert_interval
          single: CRM_alert_interval

       CRM_alert_interval
     - The interval of the resource operation
     - ``resource``
   * - .. _CRM_alert_rsc:

       .. index::
          single: environment variable; CRM_alert_rsc
          single: CRM_alert_rsc

       CRM_alert_rsc
     - The name of the affected resource
     - ``resource``
   * - .. _CRM_alert_status:

       .. index::
          single: environment variable; CRM_alert_status
          single: CRM_alert_status

       CRM_alert_status
     - A numerical code used by Pacemaker to represent the operation result
     - ``resource``
   * - .. _CRM_alert_target_rc:

       .. index::
          single: environment variable; CRM_alert_target_rc
          single: CRM_alert_target_rc

       CRM_alert_target_rc
     - The expected numerical return code of the operation
     - ``resource``
   * - .. _CRM_alert_attribute_name:

       .. index::
          single: environment variable; CRM_alert_attribute_name
          single: CRM_alert_attribute_name

       CRM_alert_attribute_name
     - The name of the node attribute that changed
     - ``attribute``
   * - .. _CRM_alert_attribute_value:

       .. index::
          single: environment variable; CRM_alert_attribute_value
          single: CRM_alert_attribute_value

       CRM_alert_attribute_value
     - The new value of the node attribute that changed
     - ``attribute``

Special concerns when writing alert agents:

* Alert agents may be called with no recipient (if none is configured),
  so the agent must be able to handle this situation, even if it
  only exits in that case. (Users may modify the configuration in
  stages, and add a recipient later.)

* If more than one recipient is configured for an alert, the alert agent will
  be called once per recipient. If an agent is not able to run concurrently, it
  should be configured with only a single recipient. The agent is free,
  however, to interpret the recipient as a list.

* When a cluster event occurs, all alerts are fired off at the same time as
  separate processes. Depending on how many alerts and recipients are
  configured, and on what is done within the alert agents,
  a significant load burst may occur. The agent could be written to take
  this into consideration, for example by queueing resource-intensive actions
  into some other instance, instead of directly executing them.

* Alert agents are run as the |CRM_DAEMON_USER| user, which has a minimal set
  of permissions. If an agent requires additional privileges, it is
  recommended to configure ``sudo`` to allow the agent to run the necessary
  commands as another user with the appropriate privileges.

* As always, take care to validate and sanitize user-configured parameters,
  such as ``CRM_alert_timestamp`` (whose content is specified by the
  user-configured ``timestamp-format``), ``CRM_alert_recipient,`` and all
  instance attributes. Mostly this is needed simply to protect against
  configuration errors, but if some user can modify the CIB without having
  |CRM_DAEMON_USER| access to the cluster nodes, it is a potential security
  concern as well, to avoid the possibility of code injection.
