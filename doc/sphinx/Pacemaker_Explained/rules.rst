.. index::
   single: rule

.. _rules:

Rules
-----

Rules can be used to make your configuration more dynamic, allowing values to
change depending on the time or the value of a node attribute. Examples of
things rules are useful for:

* Set a higher value for :ref:`resource-stickiness <resource-stickiness>`
  during working hours, to minimize downtime, and a lower value on weekends, to
  allow resources to move to their most preferred locations when people aren't
  around to notice.

* Automatically place the cluster into maintenance mode during a scheduled
  maintenance window.

* Assign certain nodes and resources to a particular department via custom
  node attributes and meta-attributes, and add a single location constraint
  that restricts the department's resources to run only on those nodes.

Each constraint type or property set that supports rules may contain one or more
``rule`` elements specifying conditions under which the constraint or properties
take effect. Examples later in this chapter will make this clearer.

.. index::
   pair: XML element; rule

Rule Properties
###############

.. table:: **Attributes of a rule Element**
   :widths: 1 1 3

   +-----------------+-------------+-------------------------------------------+
   | Attribute       | Default     | Description                               |
   +=================+=============+===========================================+
   | id              |             | .. index::                                |
   |                 |             |    pair: rule; id                         |
   |                 |             |                                           |
   |                 |             | A unique name for this element (required) |
   +-----------------+-------------+-------------------------------------------+
   | role            | ``Started`` | .. index::                                |
   |                 |             |    pair: rule; role                       |
   |                 |             |                                           |
   |                 |             | The rule is in effect only when the       |
   |                 |             | resource is in the specified role.        |
   |                 |             | Allowed values are ``Started``,           |
   |                 |             | ``Unpromoted``, and ``Promoted``. A rule  |
   |                 |             | with a ``role`` of ``Promoted`` cannot    |
   |                 |             | determine the initial location of a clone |
   |                 |             | instance and will only affect which of    |
   |                 |             | the active instances will be promoted.    |
   +-----------------+-------------+-------------------------------------------+
   | score           |             | .. index::                                |
   |                 |             |    pair: rule; score                      |
   |                 |             |                                           |
   |                 |             | If this rule is used in a location        |
   |                 |             | constraint and evaluates to true, apply   |
   |                 |             | this score to the constraint. Only one of |
   |                 |             | ``score`` and ``score-attribute`` may be  |
   |                 |             | used.                                     |
   +-----------------+-------------+-------------------------------------------+
   | score-attribute |             | .. index::                                |
   |                 |             |    pair: rule; score-attribute            |
   |                 |             |                                           |
   |                 |             | If this rule is used in a location        |
   |                 |             | constraint and evaluates to true, use the |
   |                 |             | value of this node attribute as the score |
   |                 |             | to apply to the constraint. Only one of   |
   |                 |             | ``score`` and ``score-attribute`` may be  |
   |                 |             | used.                                     |
   +-----------------+-------------+-------------------------------------------+
   | boolean-op      | ``and``     | .. index::                                |
   |                 |             |    pair: rule; boolean-op                 |
   |                 |             |                                           |
   |                 |             | If this rule contains more than one       |
   |                 |             | condition, a value of ``and`` specifies   |
   |                 |             | that the rule evaluates to true only if   |
   |                 |             | all conditions are true, and a value of   |
   |                 |             | ``or`` specifies that the rule evaluates  |
   |                 |             | to true if any condition is true.         |
   +-----------------+-------------+-------------------------------------------+

A ``rule`` element must contain one or more conditions. A condition may be an
``expression`` element, a ``date_expression`` element, or another ``rule`` element.


.. index::
   single: rule; node attribute expression
   single: node attribute; rule expression
   pair: XML element; expression

.. _node_attribute_expressions:

Node Attribute Expressions
##########################

Expressions are rule conditions based on the values of node attributes.

.. table:: **Attributes of an expression Element**
   :class: longtable
   :widths: 1 2 3

   +--------------+---------------------------------+-------------------------------------------+
   | Attribute    | Default                         | Description                               |
   +==============+=================================+===========================================+
   | id           |                                 | .. index::                                |
   |              |                                 |    pair: expression; id                   |
   |              |                                 |                                           |
   |              |                                 | A unique name for this element (required) |
   +--------------+---------------------------------+-------------------------------------------+
   | attribute    |                                 | .. index::                                |
   |              |                                 |    pair: expression; attribute            |
   |              |                                 |                                           |
   |              |                                 | The node attribute to test (required)     |
   +--------------+---------------------------------+-------------------------------------------+
   | type         | The default type for            | .. index::                                |
   |              | ``lt``, ``gt``, ``lte``, and    |    pair: expression; type                 |
   |              | ``gte`` operations is ``number``|                                           |
   |              | if either value contains a      | How the node attributes should be         |
   |              | decimal point character, or     | compared. Allowed values are ``string``,  |
   |              | ``integer`` otherwise. The      | ``integer`` *(since 2.0.5)*, ``number``,  |
   |              | default type for all other      | and ``version``. ``integer`` truncates    |
   |              | operations is ``string``. If a  | floating-point values if necessary before |
   |              | numeric parse fails for either  | performing a 64-bit integer comparison.   |
   |              | value, then the values are      | ``number`` performs a double-precision    |
   |              | compared as type ``string``.    | floating-point comparison                 |
   |              |                                 | *(32-bit integer before 2.0.5)*.          |
   +--------------+---------------------------------+-------------------------------------------+
   | operation    |                                 | .. index::                                |
   |              |                                 |    pair: expression; operation            |
   |              |                                 |                                           |
   |              |                                 | The comparison to perform (required).     |
   |              |                                 | Allowed values:                           |
   |              |                                 |                                           |
   |              |                                 | * ``lt:`` True if the node attribute value|
   |              |                                 |    is less than the comparison value      |
   |              |                                 | * ``gt:`` True if the node attribute value|
   |              |                                 |    is greater than the comparison value   |
   |              |                                 | * ``lte:`` True if the node attribute     |
   |              |                                 |    value is less than or equal to the     |
   |              |                                 |    comparison value                       |
   |              |                                 | * ``gte:`` True if the node attribute     |
   |              |                                 |    value is greater than or equal to the  |
   |              |                                 |    comparison value                       |
   |              |                                 | * ``eq:`` True if the node attribute value|
   |              |                                 |    is equal to the comparison value       |
   |              |                                 | * ``ne:`` True if the node attribute value|
   |              |                                 |    is not equal to the comparison value   |
   |              |                                 | * ``defined:`` True if the node has the   |
   |              |                                 |    named attribute                        |
   |              |                                 | * ``not_defined:`` True if the node does  |
   |              |                                 |    not have the named attribute           |
   +--------------+---------------------------------+-------------------------------------------+
   | value        |                                 | .. index::                                |
   |              |                                 |    pair: expression; value                |
   |              |                                 |                                           |
   |              |                                 | User-supplied value for comparison        |
   |              |                                 | (required for operations other than       |
   |              |                                 | ``defined`` and ``not_defined``)          |
   +--------------+---------------------------------+-------------------------------------------+
   | value-source | ``literal``                     | .. index::                                |
   |              |                                 |    pair: expression; value-source         |
   |              |                                 |                                           |
   |              |                                 | How the ``value`` is derived. Allowed     |
   |              |                                 | values:                                   |
   |              |                                 |                                           |
   |              |                                 | * ``literal``: ``value`` is a literal     |
   |              |                                 |   string to compare against               |
   |              |                                 | * ``param``: ``value`` is the name of a   |
   |              |                                 |   resource parameter to compare against   |
   |              |                                 |   (only valid in location constraints)    |
   |              |                                 | * ``meta``: ``value`` is the name of a    |
   |              |                                 |   resource meta-attribute to compare      |
   |              |                                 |   against (only valid in location         |
   |              |                                 |   constraints)                            |
   +--------------+---------------------------------+-------------------------------------------+

.. _node-attribute-expressions-special:

In addition to custom node attributes defined by the administrator, the cluster
defines special, built-in node attributes for each node that can also be used
in rule expressions.

.. table:: **Built-in Node Attributes**
   :widths: 1 4

   +---------------+-----------------------------------------------------------+
   | Name          | Value                                                     |
   +===============+===========================================================+
   | #uname        | :ref:`Node name <node_name>`                              |
   +---------------+-----------------------------------------------------------+
   | #id           | Node ID                                                   |
   +---------------+-----------------------------------------------------------+
   | #kind         | Node type. Possible values are ``cluster``, ``remote``,   |
   |               | and ``container``. Kind is ``remote`` for Pacemaker Remote|
   |               | nodes created with the ``ocf:pacemaker:remote`` resource, |
   |               | and ``container`` for Pacemaker Remote guest nodes and    |
   |               | bundle nodes                                              |
   +---------------+-----------------------------------------------------------+
   | #is_dc        | ``true`` if this node is the cluster's Designated         |
   |               | Controller (DC), ``false`` otherwise                      |
   +---------------+-----------------------------------------------------------+
   | #cluster-name | The value of the ``cluster-name`` cluster property, if set|
   +---------------+-----------------------------------------------------------+
   | #site-name    | The value of the ``site-name`` node attribute, if set,    |
   |               | otherwise identical to ``#cluster-name``                  |
   +---------------+-----------------------------------------------------------+
   | #role         | The role the relevant promotable clone resource has on    |
   |               | this node. Valid only within a rule for a location        |
   |               | constraint for a promotable clone resource.               |
   +---------------+-----------------------------------------------------------+

.. Add_to_above_table_if_released:

   +---------------+-----------------------------------------------------------+
   | #ra-version   | The installed version of the resource agent on the node,  |
   |               | as defined by the ``version`` attribute of the            |
   |               | ``resource-agent`` tag in the agent's metadata. Valid only|
   |               | within rules controlling resource options. This can be    |
   |               | useful during rolling upgrades of a backward-incompatible |
   |               | resource agent. *(since x.x.x)*                           |


.. index::
   single: rule; date/time expression
   pair: XML element; date_expression

Date/Time Expressions
#####################

Date/time expressions are rule conditions based (as the name suggests) on the
current date and time.

A ``date_expression`` element may optionally contain a ``date_spec`` or
``duration`` element depending on the context.

.. table:: **Attributes of a date_expression Element**
   :widths: 1 4

   +---------------+-----------------------------------------------------------+
   | Attribute     | Description                                               |
   +===============+===========================================================+
   | id            | .. index::                                                |
   |               |    pair: id; date_expression                              |
   |               |                                                           |
   |               | A unique name for this element (required)                 |
   +---------------+-----------------------------------------------------------+
   | start         | .. index::                                                |
   |               |    pair: start; date_expression                           |
   |               |                                                           |
   |               | A date/time conforming to the                             |
   |               | `ISO8601 <https://en.wikipedia.org/wiki/ISO_8601>`_       |
   |               | specification. May be used when ``operation`` is          |
   |               | ``in_range`` (in which case at least one of ``start`` or  |
   |               | ``end`` must be specified) or ``gt`` (in which case       |
   |               | ``start`` is required).                                   |
   +---------------+-----------------------------------------------------------+
   | end           | .. index::                                                |
   |               |    pair: end; date_expression                             |
   |               |                                                           |
   |               | A date/time conforming to the                             |
   |               | `ISO8601 <https://en.wikipedia.org/wiki/ISO_8601>`_       |
   |               | specification. May be used when ``operation`` is          |
   |               | ``in_range`` (in which case at least one of ``start`` or  |
   |               | ``end`` must be specified) or ``lt`` (in which case       |
   |               | ``end`` is required).                                     |
   +---------------+-----------------------------------------------------------+
   | operation     | .. index::                                                |
   |               |    pair: operation; date_expression                       |
   |               |                                                           |
   |               | Compares the current date/time with the start and/or end  |
   |               | date, depending on the context. Allowed values:           |
   |               |                                                           |
   |               | * ``gt:`` True if the current date/time is after ``start``|
   |               | * ``lt:`` True if the current date/time is before ``end`` |
   |               | * ``in_range:`` True if the current date/time is after    |
   |               |   ``start`` (if specified) and before either ``end`` (if  |
   |               |   specified) or ``start`` plus the value of the           |
   |               |   ``duration`` element (if one is contained in the        |
   |               |   ``date_expression``). If both ``end`` and ``duration``  |
   |               |   are specified, ``duration`` is ignored.                 |
   |               | * ``date_spec:`` True if the current date/time matches    |
   |               |   the specification given in the contained ``date_spec``  |
   |               |   element (described below)                               |
   +---------------+-----------------------------------------------------------+


.. note:: There is no ``eq``, ``neq``, ``gte``, or ``lte`` operation, since
          they would be valid only for a single second.


.. index::
   single: date specification
   pair: XML element; date_spec

Date Specifications
___________________

A ``date_spec`` element is used to create a cron-like expression relating
to time. Each field can contain a single number or range. Any field not
supplied is ignored.

.. table:: **Attributes of a date_spec Element**
   :widths: 1 3

   +---------------+-----------------------------------------------------------+
   | Attribute     | Description                                               |
   +===============+===========================================================+
   | id            | .. index::                                                |
   |               |    pair: id; date_spec                                    |
   |               |                                                           |
   |               | A unique name for this element (required)                 |
   +---------------+-----------------------------------------------------------+
   | seconds       | .. index::                                                |
   |               |    pair: seconds; date_spec                               |
   |               |                                                           |
   |               | Allowed values: 0-59                                      |
   +---------------+-----------------------------------------------------------+
   | minutes       | .. index::                                                |
   |               |    pair: minutes; date_spec                               |
   |               |                                                           |
   |               | Allowed values: 0-59                                      |
   +---------------+-----------------------------------------------------------+
   | hours         | .. index::                                                |
   |               |    pair: hours; date_spec                                 |
   |               |                                                           |
   |               | Allowed values: 0-23 (where 0 is midnight and 23 is       |
   |               | 11 p.m.)                                                  |
   +---------------+-----------------------------------------------------------+
   | monthdays     | .. index::                                                |
   |               |    pair: monthdays; date_spec                             |
   |               |                                                           |
   |               | Allowed values: 1-31 (depending on month and year)        |
   +---------------+-----------------------------------------------------------+
   | weekdays      | .. index::                                                |
   |               |    pair: weekdays; date_spec                              |
   |               |                                                           |
   |               | Allowed values: 1-7 (where 1 is Monday and  7 is Sunday)  |
   +---------------+-----------------------------------------------------------+
   | yeardays      | .. index::                                                |
   |               |    pair: yeardays; date_spec                              |
   |               |                                                           |
   |               | Allowed values: 1-366 (depending on the year)             |
   +---------------+-----------------------------------------------------------+
   | months        | .. index::                                                |
   |               |    pair: months; date_spec                                |
   |               |                                                           |
   |               | Allowed values: 1-12                                      |
   +---------------+-----------------------------------------------------------+
   | weeks         | .. index::                                                |
   |               |    pair: weeks; date_spec                                 |
   |               |                                                           |
   |               | Allowed values: 1-53 (depending on weekyear)              |
   +---------------+-----------------------------------------------------------+
   | years         | .. index::                                                |
   |               |    pair: years; date_spec                                 |
   |               |                                                           |
   |               | Year according to the Gregorian calendar                  |
   +---------------+-----------------------------------------------------------+
   | weekyears     | .. index::                                                |
   |               |    pair: weekyears; date_spec                             |
   |               |                                                           |
   |               | Year in which the week started; for example, 1 January    |
   |               | 2005 can be specified in ISO 8601 as "2005-001 Ordinal",  |
   |               | "2005-01-01 Gregorian" or "2004-W53-6 Weekly" and thus    |
   |               | would match ``years="2005"`` or ``weekyears="2004"``      |
   +---------------+-----------------------------------------------------------+
   | moon          | .. index::                                                |
   |               |    pair: moon; date_spec                                  |
   |               |                                                           |
   |               | Allowed values are 0-7 (where 0 is the new moon and 4 is  |
   |               | full moon). *(deprecated since 2.1.6)*                    |
   +---------------+-----------------------------------------------------------+

For example, ``monthdays="1"`` matches the first day of every month, and
``hours="09-17"`` matches the hours between 9 a.m. and 5 p.m. (inclusive).

At this time, multiple ranges (e.g. ``weekdays="1,2"`` or ``weekdays="1-2,5-6"``)
are not supported.

.. note:: Pacemaker can calculate when evaluation of a ``date_expression`` with
          an ``operation`` of ``gt``, ``lt``, or ``in_range`` will next change,
          and schedule a cluster re-check for that time. However, it does not
          do this for ``date_spec``.  Instead, it evaluates the ``date_spec``
          whenever a cluster re-check naturally happens via a cluster event or
          the ``cluster-recheck-interval`` cluster option.

          For example, if you have a ``date_spec`` enabling a resource from 9
          a.m. to 5 p.m., and ``cluster-recheck-interval`` has been set to 5
          minutes, then sometime between 9 a.m. and 9:05 a.m. the cluster would
          notice that it needs to start the resource, and sometime between 5
          p.m. and 5:05 p.m. it would realize that it needs to stop the
          resource. The timing of the actual start and stop actions will
          further depend on factors such as any other actions the cluster may
          need to perform first, and the load of the machine.


.. index::
   single: duration
   pair: XML element; duration

Durations
_________

A ``duration`` is used to calculate a value for ``end`` when one is not
supplied to ``in_range`` operations. It contains one or more attributes each
containing a single number. Any attribute not supplied is ignored.

.. table:: **Attributes of a duration Element**
   :widths: 1 3

   +---------------+-----------------------------------------------------------+
   | Attribute     | Description                                               |
   +===============+===========================================================+
   | id            | .. index::                                                |
   |               |    pair: id; duration                                     |
   |               |                                                           |
   |               | A unique name for this element (required)                 |
   +---------------+-----------------------------------------------------------+
   | seconds       | .. index::                                                |
   |               |    pair: seconds; duration                                |
   |               |                                                           |
   |               | This many seconds will be added to the total duration     |
   +---------------+-----------------------------------------------------------+
   | minutes       | .. index::                                                |
   |               |    pair: minutes; duration                                |
   |               |                                                           |
   |               | This many minutes will be added to the total duration     |
   +---------------+-----------------------------------------------------------+
   | hours         | .. index::                                                |
   |               |    pair: hours; duration                                  |
   |               |                                                           |
   |               | This many hours will be added to the total duration       |
   +---------------+-----------------------------------------------------------+
   | days          | .. index::                                                |
   |               |    pair: days; duration                                   |
   |               |                                                           |
   |               | This many days will be added to the total duration        |
   +---------------+-----------------------------------------------------------+
   | weeks         | .. index::                                                |
   |               |    pair: weeks; duration                                  |
   |               |                                                           |
   |               | This many weeks will be added to the total duration       |
   +---------------+-----------------------------------------------------------+
   | months        | .. index::                                                |
   |               |    pair: months; duration                                 |
   |               |                                                           |
   |               | This many months will be added to the total duration      |
   +---------------+-----------------------------------------------------------+
   | years         | .. index::                                                |
   |               |    pair: years; duration                                  |
   |               |                                                           |
   |               | This many years will be added to the total duration       |
   +---------------+-----------------------------------------------------------+


Example Time-Based Expressions
______________________________

A small sample of how time-based expressions can be used:

.. topic:: True if now is any time in the year 2005

   .. code-block:: xml

      <rule id="rule1" score="INFINITY">
         <date_expression id="date_expr1" start="2005-001" operation="in_range">
          <duration id="duration1" years="1"/>
         </date_expression>
      </rule>

   or equivalently:

   .. code-block:: xml

      <rule id="rule2" score="INFINITY">
         <date_expression id="date_expr2" operation="date_spec">
          <date_spec id="date_spec2" years="2005"/>
         </date_expression>
      </rule>

.. topic:: 9 a.m. to 5 p.m. Monday through Friday

   .. code-block:: xml

      <rule id="rule3" score="INFINITY">
         <date_expression id="date_expr3" operation="date_spec">
          <date_spec id="date_spec3" hours="9-16" weekdays="1-5"/>
         </date_expression>
      </rule>

   Note that the ``16`` matches all the way through ``16:59:59``, because the
   numeric value of the hour still matches.

.. topic:: 9 a.m. to 6 p.m. Monday through Friday or anytime Saturday

   .. code-block:: xml

      <rule id="rule4" score="INFINITY" boolean-op="or">
         <date_expression id="date_expr4-1" operation="date_spec">
          <date_spec id="date_spec4-1" hours="9-16" weekdays="1-5"/>
         </date_expression>
         <date_expression id="date_expr4-2" operation="date_spec">
          <date_spec id="date_spec4-2" weekdays="6"/>
         </date_expression>
      </rule>

.. topic:: 9 a.m. to 5 p.m. or 9 p.m. to 12 a.m. Monday through Friday

   .. code-block:: xml

      <rule id="rule5" score="INFINITY" boolean-op="and">
         <rule id="rule5-nested1" score="INFINITY" boolean-op="or">
          <date_expression id="date_expr5-1" operation="date_spec">
           <date_spec id="date_spec5-1" hours="9-16"/>
          </date_expression>
          <date_expression id="date_expr5-2" operation="date_spec">
           <date_spec id="date_spec5-2" hours="21-23"/>
          </date_expression>
         </rule>
         <date_expression id="date_expr5-3" operation="date_spec">
          <date_spec id="date_spec5-3" weekdays="1-5"/>
         </date_expression>
      </rule>

.. topic:: Mondays in March 2005

   .. code-block:: xml

      <rule id="rule6" score="INFINITY" boolean-op="and">
         <date_expression id="date_expr6-1" operation="date_spec">
          <date_spec id="date_spec6" weekdays="1"/>
         </date_expression>
         <date_expression id="date_expr6-2" operation="in_range"
           start="2005-03-01" end="2005-04-01"/>
      </rule>

   .. note:: Because no time is specified with the above dates, 00:00:00 is
             implied. This means that the range includes all of 2005-03-01 but
             none of 2005-04-01. You may wish to write ``end`` as
             ``"2005-03-31T23:59:59"`` to avoid confusion.


.. index::
   single: rule; resource expression
   single: resource; rule expression
   pair: XML element; rsc_expression

Resource Expressions
####################

An ``rsc_expression`` *(since 2.0.5)* is a rule condition based on a resource
agent's properties. This rule is only valid within an ``rsc_defaults`` or
``op_defaults`` context. None of the matching attributes of ``class``,
``provider``, and ``type`` are required. If one is omitted, all values of that
attribute will match.  For instance, omitting ``type`` means every type will
match.

.. table:: **Attributes of a rsc_expression Element**
   :widths: 1 3

   +---------------+-----------------------------------------------------------+
   | Attribute     | Description                                               |
   +===============+===========================================================+
   | id            | .. index::                                                |
   |               |    pair: id; rsc_expression                               |
   |               |                                                           |
   |               | A unique name for this element (required)                 |
   +---------------+-----------------------------------------------------------+
   | class         | .. index::                                                |
   |               |    pair: class; rsc_expression                            |
   |               |                                                           |
   |               | The standard name to be matched against resource agents   |
   +---------------+-----------------------------------------------------------+
   | provider      | .. index::                                                |
   |               |    pair: provider; rsc_expression                         |
   |               |                                                           |
   |               | If given, the vendor to be matched against resource       |
   |               | agents (only relevant when ``class`` is ``ocf``)          |
   +---------------+-----------------------------------------------------------+
   | type          | .. index::                                                |
   |               |    pair: type; rsc_expression                             |
   |               |                                                           |
   |               | The name of the resource agent to be matched              |
   +---------------+-----------------------------------------------------------+

Example Resource-Based Expressions
__________________________________

A small sample of how resource-based expressions can be used:

.. topic:: True for all ``ocf:heartbeat:IPaddr2`` resources

   .. code-block:: xml

      <rule id="rule1" score="INFINITY">
          <rsc_expression id="rule_expr1" class="ocf" provider="heartbeat" type="IPaddr2"/>
      </rule>

.. topic:: Provider doesn't apply to non-OCF resources

   .. code-block:: xml

      <rule id="rule2" score="INFINITY">
          <rsc_expression id="rule_expr2" class="stonith" type="fence_xvm"/>
      </rule>


.. index::
   single: rule; operation expression
   single: operation; rule expression
   pair: XML element; op_expression

Operation Expressions
#####################


An ``op_expression`` *(since 2.0.5)* is a rule condition based on an action of
some resource agent. This rule is only valid within an ``op_defaults`` context.

.. table:: **Attributes of an op_expression Element**
   :widths: 1 3

   +---------------+-----------------------------------------------------------+
   | Attribute     | Description                                               |
   +===============+===========================================================+
   | id            | .. index::                                                |
   |               |    pair: id; op_expression                                |
   |               |                                                           |
   |               | A unique name for this element (required)                 |
   +---------------+-----------------------------------------------------------+
   | name          | .. index::                                                |
   |               |    pair: name; op_expression                              |
   |               |                                                           |
   |               | The action name to match against. This can be any action  |
   |               | supported by the resource agent; common values include    |
   |               | ``monitor``, ``start``, and ``stop`` (required).          |
   +---------------+-----------------------------------------------------------+
   | interval      | .. index::                                                |
   |               |    pair: interval; op_expression                          |
   |               |                                                           |
   |               | The interval of the action to match against. If not given,|
   |               | only the name attribute will be used to match.            |
   +---------------+-----------------------------------------------------------+

Example Operation-Based Expressions
___________________________________

A small sample of how operation-based expressions can be used:

.. topic:: True for all monitor actions

   .. code-block:: xml

      <rule id="rule1" score="INFINITY">
          <op_expression id="rule_expr1" name="monitor"/>
      </rule>

.. topic:: True for all monitor actions with a 10 second interval

   .. code-block:: xml

      <rule id="rule2" score="INFINITY">
          <op_expression id="rule_expr2" name="monitor" interval="10s"/>
      </rule>


.. index::
   pair: location constraint; rule

Using Rules to Determine Resource Location
##########################################

A location constraint may contain one or more top-level rules. The cluster will
act as if there is a separate location constraint for each rule that evaluates
as true.

Consider the following simple location constraint:

.. topic:: Prevent resource ``webserver`` from running on node ``node3``

   .. code-block:: xml

      <rsc_location id="ban-apache-on-node3" rsc="webserver"
                    score="-INFINITY" node="node3"/>

The same constraint can be more verbosely written using a rule:

.. topic:: Prevent resource ``webserver`` from running on node ``node3`` using a rule

   .. code-block:: xml

      <rsc_location id="ban-apache-on-node3" rsc="webserver">
          <rule id="ban-apache-rule" score="-INFINITY">
            <expression id="ban-apache-expr" attribute="#uname"
              operation="eq" value="node3"/>
          </rule>
      </rsc_location>

The advantage of using the expanded form is that one could add more expressions
(for example, limiting the constraint to certain days of the week), or activate
the constraint by some node attribute other than node name.

Location Rules Based on Other Node Properties
_____________________________________________

The expanded form allows us to match on node properties other than its name.
If we rated each machine's CPU power such that the cluster had the following
nodes section:

.. topic:: Sample node section with node attributes

   .. code-block:: xml

      <nodes>
         <node id="uuid1" uname="c001n01" type="normal">
            <instance_attributes id="uuid1-custom_attrs">
              <nvpair id="uuid1-cpu_mips" name="cpu_mips" value="1234"/>
            </instance_attributes>
         </node>
         <node id="uuid2" uname="c001n02" type="normal">
            <instance_attributes id="uuid2-custom_attrs">
              <nvpair id="uuid2-cpu_mips" name="cpu_mips" value="5678"/>
            </instance_attributes>
         </node>
      </nodes>

then we could prevent resources from running on underpowered machines with this
rule:

.. topic:: Rule using a node attribute (to be used inside a location constraint)

   .. code-block:: xml

      <rule id="need-more-power-rule" score="-INFINITY">
         <expression id="need-more-power-expr" attribute="cpu_mips"
                     operation="lt" value="3000"/>
      </rule>

Using ``score-attribute`` Instead of ``score``
______________________________________________

When using ``score-attribute`` instead of ``score``, each node matched by the
rule has its score adjusted differently, according to its value for the named
node attribute. Thus, in the previous example, if a rule inside a location
constraint for a resource used ``score-attribute="cpu_mips"``, ``c001n01``
would have its preference to run the resource increased by ``1234`` whereas
``c001n02`` would have its preference increased by ``5678``.


.. _s-rsc-pattern-rules:

Specifying location scores using pattern submatches
___________________________________________________

Location constraints may use ``rsc-pattern`` to apply the constraint to all
resources whose IDs match the given pattern (see :ref:`s-rsc-pattern`). The
pattern may contain up to 9 submatches in parentheses, whose values may be used
as ``%1`` through ``%9`` in a rule's ``score-attribute`` or a rule expression's
``attribute``.

As an example, the following configuration (only relevant parts are shown)
gives the resources **server-httpd** and **ip-httpd** a preference of 100 on
**node1** and 50 on **node2**, and **ip-gateway** a preference of -100 on
**node1** and 200 on **node2**.

.. topic:: Location constraint using submatches

   .. code-block:: xml

      <nodes>
         <node id="1" uname="node1">
            <instance_attributes id="node1-attrs">
               <nvpair id="node1-prefer-httpd" name="prefer-httpd" value="100"/>
               <nvpair id="node1-prefer-gateway" name="prefer-gateway" value="-100"/>
            </instance_attributes>
         </node>
         <node id="2" uname="node2">
            <instance_attributes id="node2-attrs">
               <nvpair id="node2-prefer-httpd" name="prefer-httpd" value="50"/>
               <nvpair id="node2-prefer-gateway" name="prefer-gateway" value="200"/>
            </instance_attributes>
         </node>
      </nodes>
      <resources>
         <primitive id="server-httpd" class="ocf" provider="heartbeat" type="apache"/>
         <primitive id="ip-httpd" class="ocf" provider="heartbeat" type="IPaddr2"/>
         <primitive id="ip-gateway" class="ocf" provider="heartbeat" type="IPaddr2"/>
      </resources>
      <constraints>
         <!-- The following constraint says that for any resource whose name
              starts with "server-" or "ip-", that resource's preference for a
              node is the value of the node attribute named "prefer-" followed
              by the part of the resource name after "server-" or "ip-",
              wherever such a node attribute is defined.
           -->
         <rsc_location id="location1" rsc-pattern="(server|ip)-(.*)">
            <rule id="location1-rule1" score-attribute="prefer-%2">
               <expression id="location1-rule1-expression1" attribute="prefer-%2" operation="defined"/>
            </rule>
         </rsc_location>
      </constraints>


.. index::
   pair: cluster option; rule
   pair: instance attribute; rule
   pair: meta-attribute; rule
   pair: resource defaults; rule
   pair: operation defaults; rule
   pair: node attribute; rule

Using Rules to Define Options
#############################

Rules may be used to control a variety of options:

* :ref:`Cluster options <cluster_options>` (``cluster_property_set`` elements)
* :ref:`Node attributes <node_attributes>` (``instance_attributes`` or
  ``utilization`` elements inside a ``node`` element)
* :ref:`Resource options <resource_options>` (``utilization``,
  ``meta_attributes``, or ``instance_attributes`` elements inside a resource
  definition element or ``op`` , ``rsc_defaults``, ``op_defaults``, or
  ``template`` element)
* :ref:`Operation properties <operation_properties>` (``meta_attributes``
  elements inside an ``op`` or ``op_defaults`` element)

.. note::

   Attribute-based expressions for meta-attributes can only be used within
   ``operations`` and ``op_defaults``.  They will not work with resource
   configuration or ``rsc_defaults``.  Additionally, attribute-based
   expressions cannot be used with cluster options.

Using Rules to Control Resource Options
_______________________________________

Often some cluster nodes will be different from their peers. Sometimes,
these differences -- e.g. the location of a binary or the names of network
interfaces -- require resources to be configured differently depending
on the machine they're hosted on.

By defining multiple ``instance_attributes`` objects for the resource and
adding a rule to each, we can easily handle these special cases.

In the example below, ``mySpecialRsc`` will use eth1 and port 9999 when run on
``node1``, eth2 and port 8888 on ``node2`` and default to eth0 and port 9999
for all other nodes.

.. topic:: Defining different resource options based on the node name

   .. code-block:: xml

      <primitive id="mySpecialRsc" class="ocf" type="Special" provider="me">
         <instance_attributes id="special-node1" score="3">
          <rule id="node1-special-case" score="INFINITY" >
           <expression id="node1-special-case-expr" attribute="#uname"
             operation="eq" value="node1"/>
          </rule>
          <nvpair id="node1-interface" name="interface" value="eth1"/>
         </instance_attributes>
         <instance_attributes id="special-node2" score="2" >
          <rule id="node2-special-case" score="INFINITY">
           <expression id="node2-special-case-expr" attribute="#uname"
             operation="eq" value="node2"/>
          </rule>
          <nvpair id="node2-interface" name="interface" value="eth2"/>
          <nvpair id="node2-port" name="port" value="8888"/>
         </instance_attributes>
         <instance_attributes id="defaults" score="1" >
          <nvpair id="default-interface" name="interface" value="eth0"/>
          <nvpair id="default-port" name="port" value="9999"/>
         </instance_attributes>
      </primitive>

The order in which ``instance_attributes`` objects are evaluated is determined
by their score (highest to lowest). If not supplied, the score defaults to
zero. Objects with an equal score are processed in their listed order. If the
``instance_attributes`` object has no rule, or a ``rule`` that evaluates to
``true``, then for any parameter the resource does not yet have a value for,
the resource will use the parameter values defined by the ``instance_attributes``.

For example, given the configuration above, if the resource is placed on
``node1``:

* ``special-node1`` has the highest score (3) and so is evaluated first; its
  rule evaluates to ``true``, so ``interface`` is set to ``eth1``.
* ``special-node2`` is evaluated next with score 2, but its rule evaluates to
  ``false``, so it is ignored.
* ``defaults`` is evaluated last with score 1, and has no rule, so its values
  are examined; ``interface`` is already defined, so the value here is not
  used, but ``port`` is not yet defined, so ``port`` is set to ``9999``.

Using Rules to Control Resource Defaults
________________________________________

Rules can be used for resource and operation defaults. The following example
illustrates how to set a different ``resource-stickiness`` value during and
outside work hours. This allows resources to automatically move back to their
most preferred hosts, but at a time that (in theory) does not interfere with
business activities.

.. topic:: Change ``resource-stickiness`` during working hours

   .. code-block:: xml

      <rsc_defaults>
         <meta_attributes id="core-hours" score="2">
            <rule id="core-hour-rule" score="0">
              <date_expression id="nine-to-five-Mon-to-Fri" operation="date_spec">
                <date_spec id="nine-to-five-Mon-to-Fri-spec" hours="9-16" weekdays="1-5"/>
              </date_expression>
            </rule>
            <nvpair id="core-stickiness" name="resource-stickiness" value="INFINITY"/>
         </meta_attributes>
         <meta_attributes id="after-hours" score="1" >
            <nvpair id="after-stickiness" name="resource-stickiness" value="0"/>
         </meta_attributes>
      </rsc_defaults>

Rules may be used similarly in ``instance_attributes`` or ``utilization``
blocks.

Any single block may directly contain only a single rule, but that rule may
itself contain any number of rules.

``rsc_expression`` and ``op_expression`` blocks may additionally be used to
set defaults on either a single resource or across an entire class of resources
with a single rule. ``rsc_expression`` may be used to select resource agents
within both ``rsc_defaults`` and ``op_defaults``, while ``op_expression`` may
only be used within ``op_defaults``. If multiple rules succeed for a given
resource agent, the last one specified will be the one that takes effect. As
with any other rule, boolean operations may be used to make more complicated
expressions.

.. topic:: Default all IPaddr2 resources to stopped

   .. code-block:: xml

      <rsc_defaults>
          <meta_attributes id="op-target-role">
              <rule id="op-target-role-rule" score="INFINITY">
                  <rsc_expression id="op-target-role-expr" class="ocf" provider="heartbeat"
                    type="IPaddr2"/>
              </rule>
              <nvpair id="op-target-role-nvpair" name="target-role" value="Stopped"/>
          </meta_attributes>
      </rsc_defaults>

.. topic:: Default all monitor action timeouts to 7 seconds

   .. code-block:: xml

      <op_defaults>
          <meta_attributes id="op-monitor-defaults">
              <rule id="op-monitor-default-rule" score="INFINITY">
                  <op_expression id="op-monitor-default-expr" name="monitor"/>
              </rule>
              <nvpair id="op-monitor-timeout" name="timeout" value="7s"/>
          </meta_attributes>
      </op_defaults>

.. topic:: Default the timeout on all 10-second-interval monitor actions on ``IPaddr2`` resources to 8 seconds

   .. code-block:: xml

      <op_defaults>
          <meta_attributes id="op-monitor-and">
              <rule id="op-monitor-and-rule" score="INFINITY">
                  <rsc_expression id="op-monitor-and-rsc-expr" class="ocf" provider="heartbeat"
                    type="IPaddr2"/>
                  <op_expression id="op-monitor-and-op-expr" name="monitor" interval="10s"/>
              </rule>
              <nvpair id="op-monitor-and-timeout" name="timeout" value="8s"/>
          </meta_attributes>
      </op_defaults>


.. index::
   pair: rule; cluster option

Using Rules to Control Cluster Options
______________________________________

Controlling cluster options is achieved in much the same manner as specifying
different resource options on different nodes.

The following example illustrates how to set ``maintenance_mode`` during a
scheduled maintenance window. This will keep the cluster running but not
monitor, start, or stop resources during this time.

.. topic:: Schedule a maintenance window for 9 to 11 p.m. CDT Sept. 20, 2019

   .. code-block:: xml

      <crm_config>
         <cluster_property_set id="cib-bootstrap-options">
           <nvpair id="bootstrap-stonith-enabled" name="stonith-enabled" value="1"/>
         </cluster_property_set>
         <cluster_property_set id="normal-set" score="10">
           <nvpair id="normal-maintenance-mode" name="maintenance-mode" value="false"/>
         </cluster_property_set>
         <cluster_property_set id="maintenance-window-set" score="1000">
           <nvpair id="maintenance-nvpair1" name="maintenance-mode" value="true"/>
           <rule id="maintenance-rule1" score="INFINITY">
             <date_expression id="maintenance-date1" operation="in_range"
               start="2019-09-20 21:00:00 -05:00" end="2019-09-20 23:00:00 -05:00"/>
           </rule>
         </cluster_property_set>
      </crm_config>

.. important:: The ``cluster_property_set`` with an ``id`` set to
               "cib-bootstrap-options" will *always* have the highest priority,
               regardless of any scores. Therefore, rules in another
               ``cluster_property_set`` can never take effect for any
               properties listed in the bootstrap set.
