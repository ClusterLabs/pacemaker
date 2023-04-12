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
   
For more information about sample alert agents provided by Pacemaker and about
developing custom alert agents, see the *Pacemaker Administration* document.


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
   
As with resources, meta-attributes can be configured for alerts to change
whether and how Pacemaker calls them.
   
.. table:: **Meta-Attributes of an Alert**
   :class: longtable
   :widths: 1 1 3
   
   +------------------+---------------+-----------------------------------------------------+
   | Meta-Attribute   | Default       | Description                                         |
   +==================+===============+=====================================================+
   | enabled          | true          | .. index::                                          |
   |                  |               |    single: alert; meta-attribute, enabled           |
   |                  |               |    single: meta-attribute; enabled (alert)          |
   |                  |               |    single: enabled; alert meta-attribute            |
   |                  |               |                                                     |
   |                  |               | If false for an alert, the alert will not be used.  |
   |                  |               | If true for an alert and false for a particular     |
   |                  |               | recipient of that alert, that recipient will not be |
   |                  |               | used.                                               |
   +------------------+---------------+-----------------------------------------------------+
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
   
Meta-attributes can be configured per alert and/or per recipient.
   
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
