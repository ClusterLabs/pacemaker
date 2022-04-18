.. index::
   single: alert
   single: resource; alert
   single: node; alert
   single: fencing; alert
   pair: XML element; alert
   pair: XML element; alerts

Alerts
------

*Alerts* may be configured to take some external action when a cluster event
occurs (node failure, resource starting or stopping, etc.).


.. index::
   pair: alert; agent

Alert Agents
############

As with resource agents, the cluster calls an external program (an
*alert agent*) to handle alerts. The cluster passes information about the event
to the agent via environment variables. Agents can do anything desired with
this information (send an e-mail, log to a file, update a monitoring system,
etc.).

.. topic:: Simple alert configuration

   .. code-block:: xml

      <configuration>
         <alerts>
            <alert id="my-alert" path="/path/to/my-script.sh" />
         </alerts>
      </configuration>

In the example above, the cluster will call ``my-script.sh`` for each event.

Multiple alert agents may be configured; the cluster will call all of them for
each event.

Alert agents will be called only on cluster nodes. They will be called for
events involving Pacemaker Remote nodes, but they will never be called *on*
those nodes.
   

.. index::
   single: alert; recipient
   pair: XML element; recipient

Alert Recipients
################
   
Usually, alerts are directed towards a recipient. Thus, each alert may be
additionally configured with one or more recipients. The cluster will call the
agent separately for each recipient.
   
.. topic:: Alert configuration with recipient

   .. code-block:: xml

      <configuration>
         <alerts>
            <alert id="my-alert" path="/path/to/my-script.sh">
                <recipient id="my-alert-recipient" value="some-address"/>
            </alert>
         </alerts>
      </configuration>
   
In the above example, the cluster will call ``my-script.sh`` for each event,
passing the recipient ``some-address`` as an environment variable.

The recipient may be anything the alert agent can recognize -- an IP address,
an e-mail address, a file name, whatever the particular agent supports.
   
   
.. index::
   single: alert; meta-attributes
   single: meta-attribute; alert meta-attributes

Alert Meta-Attributes
#####################
   
As with resource agents, meta-attributes can be configured for alert agents
to affect how Pacemaker calls them.
   
.. table:: **Meta-Attributes of an Alert**
   :class: longtable
   :widths: 1 1 3
   
   +------------------+---------------+-----------------------------------------------------+
   | Meta-Attribute   | Default       | Description                                         |
   +==================+===============+=====================================================+
   | timestamp-format | %H:%M:%S.%06N | .. index::                                          |
   |                  |               |    single: alert; meta-attribute, timestamp-format  |
   |                  |               |    single: meta-attribute; timestamp-format (alert) |
   |                  |               |    single: timestamp-format; alert meta-attribute   |
   |                  |               |                                                     |
   |                  |               | Format the cluster will use when sending the        |
   |                  |               | event's timestamp to the agent. This is a string as |
   |                  |               | used with the ``date(1)`` command.                  |
   +------------------+---------------+-----------------------------------------------------+
   | timeout          | 30s           | .. index::                                          |
   |                  |               |    single: alert; meta-attribute, timeout           |
   |                  |               |    single: meta-attribute; timeout (alert)          |
   |                  |               |    single: timeout; alert meta-attribute            |
   |                  |               |                                                     |
   |                  |               | If the alert agent does not complete within this    |
   |                  |               | amount of time, it will be terminated.              |
   +------------------+---------------+-----------------------------------------------------+
   
Meta-attributes can be configured per alert agent and/or per recipient.
   
.. topic:: Alert configuration with meta-attributes

   .. code-block:: xml

      <configuration>
         <alerts>
            <alert id="my-alert" path="/path/to/my-script.sh">
               <meta_attributes id="my-alert-attributes">
                  <nvpair id="my-alert-attributes-timeout" name="timeout"
                          value="15s"/>
               </meta_attributes>
               <recipient id="my-alert-recipient1" value="someuser@example.com">
                  <meta_attributes id="my-alert-recipient1-attributes">
                     <nvpair id="my-alert-recipient1-timestamp-format"
                             name="timestamp-format" value="%D %H:%M"/>
                  </meta_attributes>
               </recipient>
               <recipient id="my-alert-recipient2" value="otheruser@example.com">
                  <meta_attributes id="my-alert-recipient2-attributes">
                     <nvpair id="my-alert-recipient2-timestamp-format"
                             name="timestamp-format" value="%c"/>
                  </meta_attributes>
               </recipient>
            </alert>
         </alerts>
      </configuration>
   
In the above example, the ``my-script.sh`` will get called twice for each
event, with each call using a 15-second timeout. One call will be passed the
recipient ``someuser@example.com`` and a timestamp in the format ``%D %H:%M``,
while the other call will be passed the recipient ``otheruser@example.com`` and
a timestamp in the format ``%c``.
   
   
.. index::
   single: alert; instance attributes
   single: instance attribute; alert instance attributes

Alert Instance Attributes
#########################
   
As with resource agents, agent-specific configuration values may be configured
as instance attributes. These will be passed to the agent as additional
environment variables. The number, names and allowed values of these instance
attributes are completely up to the particular agent.
   
.. topic:: Alert configuration with instance attributes

   .. code-block:: xml

      <configuration>
         <alerts>
            <alert id="my-alert" path="/path/to/my-script.sh">
               <meta_attributes id="my-alert-attributes">
                  <nvpair id="my-alert-attributes-timeout" name="timeout"
                          value="15s"/>
               </meta_attributes>
               <instance_attributes id="my-alert-options">
                   <nvpair id="my-alert-options-debug" name="debug"
                           value="false"/>
               </instance_attributes>
               <recipient id="my-alert-recipient1"
                          value="someuser@example.com"/>
            </alert>
         </alerts>
      </configuration>
   
   
.. index::
   single: alert; filters
   pair: XML element; select
   pair: XML element; select_nodes
   pair: XML element; select_fencing
   pair: XML element; select_resources
   pair: XML element; select_attributes
   pair: XML element; attribute

Alert Filters
#############
   
By default, an alert agent will be called for node events, fencing events, and
resource events. An agent may choose to ignore certain types of events, but
there is still the overhead of calling it for those events. To eliminate that
overhead, you may select which types of events the agent should receive.
   
.. topic:: Alert configuration to receive only node events and fencing events

   .. code-block:: xml

      <configuration>
         <alerts>
            <alert id="my-alert" path="/path/to/my-script.sh">
               <select>
                  <select_nodes />
                  <select_fencing />
               </select>
               <recipient id="my-alert-recipient1"
                          value="someuser@example.com"/>
            </alert>
         </alerts>
      </configuration>
   
The possible options within ``<select>`` are ``<select_nodes>``,
``<select_fencing>``, ``<select_resources>``, and ``<select_attributes>``.

With ``<select_attributes>`` (the only event type not enabled by default), the
agent will receive alerts when a node attribute changes. If you wish the agent
to be called only when certain attributes change, you can configure that as well.
   
.. topic:: Alert configuration to be called when certain node attributes change

   .. code-block:: xml

      <configuration>
         <alerts>
            <alert id="my-alert" path="/path/to/my-script.sh">
               <select>
                  <select_attributes>
                     <attribute id="alert-standby" name="standby" />
                     <attribute id="alert-shutdown" name="shutdown" />
                  </select_attributes>
               </select>
               <recipient id="my-alert-recipient1" value="someuser@example.com"/>
            </alert>
         </alerts>
      </configuration>
   
Node attribute alerts are currently considered experimental. Alerts may be
limited to attributes set via ``attrd_updater``, and agents may be called
multiple times with the same attribute value.
   
.. index::
   single: alert; sample agents

Using the Sample Alert Agents
#############################
   
Pacemaker provides several sample alert agents, installed in
``/usr/share/pacemaker/alerts`` by default.
   
While these sample scripts may be copied and used as-is, they are provided
mainly as templates to be edited to suit your purposes. See their source code
for the full set of instance attributes they support.
   
.. topic:: Sending cluster events as SNMP traps

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
   
   
Writing an Alert Agent
######################
   
.. index::
   single: alert; environment variables
   single: environment variable; alert agents

.. table:: **Environment variables passed to alert agents**
   :class: longtable
   :widths: 1 3
   
   +---------------------------+----------------------------------------------------------------+
   | Environment Variable      | Description                                                    |
   +===========================+================================================================+
   | CRM_alert_kind            | .. index::                                                     | 
   |                           |   single:environment variable; CRM_alert_kind                  |
   |                           |   single:CRM_alert_kind                                        |
   |                           |                                                                |
   |                           | The type of alert (``node``, ``fencing``, ``resource``, or     |
   |                           | ``attribute``)                                                 |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_node            | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_node                  |
   |                           |   single:CRM_alert_node                                        |
   |                           |                                                                |
   |                           | Name of affected node                                          |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_node_sequence   | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_sequence              |
   |                           |   single:CRM_alert_sequence                                    |
   |                           |                                                                |
   |                           | A sequence number increased whenever an alert is being issued  |
   |                           | on the local node, which can be used to reference the order in |
   |                           | which alerts have been issued by Pacemaker. An alert for an    |
   |                           | event that happened later in time reliably has a higher        |
   |                           | sequence number than alerts for earlier events.                |
   |                           |                                                                |
   |                           | Be aware that this number has no cluster-wide meaning.         |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_recipient       | .. index::                                                     | 
   |                           |   single:environment variable; CRM_alert_recipient             |
   |                           |   single:CRM_alert_recipient                                   |
   |                           |                                                                |
   |                           | The configured recipient                                       |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_timestamp       | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_timestamp             |
   |                           |   single:CRM_alert_timestamp                                   |
   |                           |                                                                |
   |                           | A timestamp created prior to executing the agent, in the       |
   |                           | format specified by the ``timestamp-format`` meta-attribute.   |
   |                           | This allows the agent to have a reliable, high-precision time  |
   |                           | of when the event occurred, regardless of when the agent       |
   |                           | itself was invoked (which could potentially be delayed due to  |
   |                           | system load, etc.).                                            |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_timestamp_epoch | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_timestamp_epoch       |
   |                           |   single:CRM_alert_timestamp_epoch                             |
   |                           |                                                                |
   |                           | The same time as ``CRM_alert_timestamp``, expressed as the     |
   |                           | integer number of seconds since January 1, 1970. This (along   |
   |                           | with ``CRM_alert_timestamp_usec``) can be useful for alert     |
   |                           | agents that need to format time in a specific way rather than  |
   |                           | let the user configure it.                                     |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_timestamp_usec  | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_timestamp_usec        |
   |                           |   single:CRM_alert_timestamp_usec                              |
   |                           |                                                                |
   |                           | The same time as ``CRM_alert_timestamp``, expressed as the     |
   |                           | integer number of microseconds since                           |
   |                           | ``CRM_alert_timestamp_epoch``.                                 |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_version         | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_version               |
   |                           |   single:CRM_alert_version                                     |
   |                           |                                                                |
   |                           | The version of Pacemaker sending the alert                     |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_desc            | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_desc                  |
   |                           |   single:CRM_alert_desc                                        |
   |                           |                                                                |
   |                           | Detail about event. For ``node`` alerts, this is the node's    |
   |                           | current state (``member`` or ``lost``). For ``fencing``        |
   |                           | alerts, this is a summary of the requested fencing operation,  |
   |                           | including origin, target, and fencing operation error code, if |
   |                           | any. For ``resource`` alerts, this is a readable string        |
   |                           | equivalent of ``CRM_alert_status``.                            |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_nodeid          | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_nodeid                |
   |                           |   single:CRM_alert_nodeid                                      |
   |                           |                                                                |
   |                           | ID of node whose status changed (provided with ``node`` alerts |
   |                           | only)                                                          |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_rc              | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_rc                    |
   |                           |   single:CRM_alert_rc                                          |
   |                           |                                                                |
   |                           | The numerical return code of the fencing or resource operation |
   |                           | (provided with ``fencing`` and ``resource`` alerts only)       |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_task            | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_task                  |
   |                           |   single:CRM_alert_task                                        |
   |                           |                                                                |
   |                           | The requested fencing or resource operation (provided with     |
   |                           | ``fencing`` and ``resource`` alerts only)                      |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_exec_time       | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_exec_time             |
   |                           |   single:CRM_alert_exec_time                                   |
   |                           |                                                                |
   |                           | The (wall-clock) time, in milliseconds, that it took to        |
   |                           | execute the action. If the action timed out,                   |
   |                           | ``CRM_alert_status`` will be 2, ``CRM_alert_desc`` will be     |
   |                           | "Timed Out", and this value will be the action timeout. May    |
   |                           | not be supported on all platforms. (``resource`` alerts only)  |
   |                           | *(since 2.0.1)*                                                |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_interval        | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_interval              |
   |                           |   single:CRM_alert_interval                                    |
   |                           |                                                                |
   |                           | The interval of the resource operation (``resource`` alerts    |
   |                           | only)                                                          |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_rsc             | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_rsc                   |
   |                           |   single:CRM_alert_rsc                                         |
   |                           |                                                                |
   |                           | The name of the affected resource (``resource`` alerts only)   |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_status          | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_status                |
   |                           |   single:CRM_alert_status                                      |
   |                           |                                                                |
   |                           | A numerical code used by Pacemaker to represent the operation  |
   |                           | result (``resource`` alerts only)                              |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_target_rc       | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_target_rc             |
   |                           |   single:CRM_alert_target_rc                                   |
   |                           |                                                                |
   |                           | The expected numerical return code of the operation            |
   |                           | (``resource`` alerts only)                                     |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_attribute_name  | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_attribute_name        |
   |                           |   single:CRM_alert_attribute_name                              |
   |                           |                                                                |
   |                           | The name of the node attribute that changed (``attribute``     |
   |                           | alerts only)                                                   |
   +---------------------------+----------------------------------------------------------------+
   | CRM_alert_attribute_value | .. index::                                                     |
   |                           |   single:environment variable; CRM_alert_attribute_value       |
   |                           |   single:CRM_alert_attribute_value                             |
   |                           |                                                                |
   |                           | The new value of the node attribute that changed               |
   |                           | (``attribute`` alerts only)                                    |
   +---------------------------+----------------------------------------------------------------+
   
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
   
* Alert agents are run as the ``hacluster`` user, which has a minimal set
  of permissions. If an agent requires additional privileges, it is
  recommended to configure ``sudo`` to allow the agent to run the necessary
  commands as another user with the appropriate privileges.
   
* As always, take care to validate and sanitize user-configured parameters,
  such as ``CRM_alert_timestamp`` (whose content is specified by the
  user-configured ``timestamp-format``), ``CRM_alert_recipient,`` and all
  instance attributes. Mostly this is needed simply to protect against
  configuration errors, but if some user can modify the CIB without having
  ``hacluster``-level access to the cluster nodes, it is a potential security
  concern as well, to avoid the possibility of code injection.
   
.. note:: **ocf:pacemaker:ClusterMon compatibility**

   The alerts interface is designed to be backward compatible with the external
   scripts interface used by the ``ocf:pacemaker:ClusterMon`` resource, which
   is now deprecated. To preserve this compatibility, the environment variables
   passed to alert agents are available prepended with ``CRM_notify_``
   as well as ``CRM_alert_``. One break in compatibility is that ``ClusterMon``
   ran external scripts as the ``root`` user, while alert agents are run as the
   ``hacluster`` user.
