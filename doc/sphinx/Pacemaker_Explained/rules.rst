.. index::
   single: rule

.. _rules:

Rules
-----

Rules make a configuration more dynamic, allowing values to depend on
conditions such as time of day or the value of a node attribute. For example,
rules can:

* Set a higher value for :ref:`resource-stickiness <resource-stickiness>`
  during working hours to minimize downtime, and a lower value on weekends to
  allow resources to move to their most preferred locations when people aren't
  around

* Automatically place the cluster into maintenance mode during a scheduled
  maintenance window

* Restrict a particular department's resources to run on certain nodes, as
  determined by custom resource meta-attributes and node attributes

.. index::
   pair: rule; XML element
   pair: rule; options

Rule Options
############

Each context that supports rules may contain a single ``rule`` element.

.. list-table:: **Attributes of a rule Element**
   :class: longtable
   :widths: 2 2 2 5
   :header-rows: 1
   
   * - Name
     - Type
     - Default
     - Description
   
   * - .. _rule_id:
     
       .. index::
          pair: rule; id
        
       id
     - :ref:`id <id>`
     -
     - A unique name for this element (required)
   * - .. _boolean_op:
     
       .. index::
          pair: rule; boolean-op
        
       boolean-op
     - :ref:`enumeration <enumeration>`
     - ``and``
     - How to combine conditions if this rule contains more than one. Allowed
       values:
       
       * ``and``: the rule is satisfied only if all conditions are satisfied
       * ``or``: the rule is satisfied if any condition is satisfied

.. _rule_conditions:

.. index::
   single: rule; conditions
   single: rule; contexts

Rule Conditions and Contexts
############################

A ``rule`` element must contain one or more conditions. A condition is any of
the following, which will be described in more detail later:

* a :ref:`date/time expression <date_expression>`
* a :ref:`node attribute expression <node_attribute_expressions>`
* a :ref:`resource type expression <rsc_expression>`
* an :ref:`operation type expression <op_expression>`
* another ``rule`` (allowing for complex combinations of conditions)

Each type of condition is allowed only in certain contexts. Although any given
context may contain only one ``rule`` element, that element may contain any
number of conditions, including other ``rule`` elements.

Rules may be used in the following contexts, which also will be described in
more detail later:

* a :ref:`location constraint <location_rule>`
* a :ref:`cluster_property_set <cluster_options>` element (within the
  ``crm_config`` element)
* an :ref:`instance_attributes <option_rule>` element (within an ``alert``,
  ``bundle``, ``clone``, ``group``, ``node``, ``op``, ``primitive``,
  ``recipient``, or ``template`` element)
* a :ref:`meta_attributes <option_rule>` element (within an ``alert``,
  ``bundle``, ``clone``, ``group``, ``op``, ``op_defaults``, ``primitive``,
  ``recipient``, ``rsc_defaults``, or ``template`` element)
* a :ref:`utilization <option_rule>` element (within a ``node``, ``primitive``,
  or ``template`` element)


.. _date_expression:

.. index::
   single: rule; date/time expression
   pair: XML element; date_expression

Date/Time Expressions
#####################

The ``date_expression`` element configures a rule condition based on the
current date and time. It is allowed in rules in any context.

It may contain a ``date_spec`` or ``duration`` element depending on the
``operation`` as described below.

.. list-table:: **Attributes of a date_expression Element**
   :class: longtable
   :widths: 1 1 1 4
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description
   * - .. _date_expression_id:

       .. index::
          pair: date_expression; id

       id
     - :ref:`id <id>`
     - 
     - A unique name for this element (required)
   * - .. _date_expression_start:

       .. index::
          pair: date_expression; start

       start
     - :ref:`ISO 8601 <iso8601>`
     - 
     - The beginning of the desired time range. Meaningful with an
       ``operation`` of ``in_range`` or ``gt``.
   * - .. _date_expression_end:

       .. index::
          pair: date_expression; end

       end
     - :ref:`ISO 8601 <iso8601>`
     - 
     - The end of the desired time range. Meaningful with an ``operation`` of
       ``in_range`` or ``lt``.
   * - .. _date_expression_operation:

       .. index::
          pair: date_expression; operation

       operation
     - :ref:`enumeration <enumeration>`
     - ``in_range``
     - Specifies how to compare the current date/time against a desired time
       range. Allowed values:

       * ``gt:`` The expression is satisfied if the current date/time is after
         ``start`` (which is required)
       * ``lt:`` The expression is satisfied if the current date/time is before
         ``end`` (which is required)
       * ``in_range:`` The expression is satisfied if the current date/time is
         greater than or equal to ``start`` (if specified) and less than or
         equal to either ``end`` (if specified) or ``start`` plus the value of
         the :ref:`duration <duration_element>` element (if one is contained in
         the ``date_expression``). At least one of ``start`` or ``end`` must be
         specified. If both ``end`` and ``duration`` are specified,
         ``duration`` is ignored.
       * ``date_spec:`` The expression is satisfied if the current date/time
         matches the specification given in the contained
         :ref:`date_spec <date_spec>` element (which is required)

.. _date_spec:

.. index::
   single: date specification
   pair: XML element; date_spec

Date Specifications
___________________

A ``date_spec`` element is used within a ``date_expression`` to specify a
combination of dates and times that satisfy the expression.

.. list-table:: **Attributes of a date_spec Element**
   :class: longtable
   :widths: 1 1 1 4
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description
   * - .. _date_spec_id:

       .. index::
          pair: date_spec; id

       id
     - :ref:`id <id>`
     - 
     - A unique name for this element (required)
   * - .. _date_spec_seconds:

       .. index::
          pair: date_spec; seconds

       seconds
     - :ref:`range <range>`
     - 
     - If this is set, the expression is satisfied only if the current time's
       second is within this range. Allowed integers: 0 to 59.
   * - .. _date_spec_minutes:

       .. index::
          pair: date_spec; minutes

       minutes
     - :ref:`range <range>`
     - 
     - If this is set, the expression is satisfied only if the current time's
       minute is within this range. Allowed integers: 0 to 59.
   * - .. _date_spec_hours:

       .. index::
          pair: date_spec; hours

       hours
     - :ref:`range <range>`
     - 
     - If this is set, the expression is satisfied only if the current time's
       hour is within this range. Allowed integers: 0 to 23 where 0 is midnight
       and 23 is 11 p.m.
   * - .. _date_spec_monthdays:

       .. index::
          pair: date_spec; monthdays

       monthdays
     - :ref:`range <range>`
     - 
     - If this is set, the expression is satisfied only if the current date's
       day of the month is in this range. Allowed integers: 1 to 31.
   * - .. _date_spec_weekdays:

       .. index::
          pair: date_spec; weekdays

       weekdays
     - :ref:`range <range>`
     - 
     - If this is set, the expression is satisfied only if the current date's
       ordinal day of the week is in this range. Allowed integers: 1-7 (where 1
       is Monday and  7 is Sunday).
   * - .. _date_spec_yeardays:

       .. index::
          pair: date_spec; yeardays

       yeardays
     - :ref:`range <range>`
     - 
     - If this is set, the expression is satisfied only if the current date's
       ordinal day of the year is in this range. Allowed integers: 1-366.
   * - .. _date_spec_months:

       .. index::
          pair: date_spec; months

       months
     - :ref:`range <range>`
     - 
     - If this is set, the expression is satisfied only if the current date's
       month is in this range. Allowed integers: 1-12 where 1 is January and 12
       is December.
   * - .. _date_spec_weeks:

       .. index::
          pair: date_spec; weeks

       weeks
     - :ref:`range <range>`
     - 
     - If this is set, the expression is satisfied only if the current date's
       ordinal week of the year is in this range. Allowed integers: 1-53.
   * - .. _date_spec_years:

       .. index::
          pair: date_spec; years

       years
     - :ref:`range <range>`
     - 
     - If this is set, the expression is satisfied only if the current date's
       year according to the Gregorian calendar is in this range.
   * - .. _date_spec_weekyears:

       .. index::
          pair: date_spec; weekyears

       weekyears
     - :ref:`range <range>`
     - 
     - If this is set, the expression is satisfied only if the current date's
       year in which the week started (according to the ISO 8601 standard) is
       in this range.
   * - .. _date_spec_moon:

       .. index::
          pair: date_spec; moon

       moon
     - :ref:`range <range>`
     - 
     - If this is set, the expression is satisfied only if the current date's
       phase of the moon is in this range. Allowed values are 0 to 7 where 0 is
       the new moon and 4 is the full moon. *(deprecated since 2.1.6)*

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


.. _duration_element:

.. index::
   single: duration
   pair: XML element; duration

Durations
_________

A ``duration`` element is used within a ``date_expression`` to calculate an
ending value for ``in_range`` operations when ``end`` is not supplied.

.. list-table:: **Attributes of a duration Element**
   :class: longtable
   :widths: 1 1 1 4
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description
   * - .. _duration_id:

       .. index::
          pair: duration; id

       id
     - :ref:`id <id>`
     - 
     - A unique name for this element (required)
   * - .. _duration_seconds:

       .. index::
          pair: duration; seconds

       seconds
     - :ref:`integer <integer>`
     - 0
     - Number of seconds to add to the total duration
   * - .. _duration_minutes:

       .. index::
          pair: duration; minutes

       minutes
     - :ref:`integer <integer>`
     - 0
     - Number of minutes to add to the total duration
   * - .. _duration_hours:

       .. index::
          pair: duration; hours

       hours
     - :ref:`integer <integer>`
     - 0
     - Number of hours to add to the total duration
   * - .. _duration_days:

       .. index::
          pair: duration; days

       days
     - :ref:`integer <integer>`
     - 0
     - Number of days to add to the total duration
   * - .. _duration_weeks:

       .. index::
          pair: duration; weeks

       weeks
     - :ref:`integer <integer>`
     - 0
     - Number of weeks to add to the total duration
   * - .. _duration_months:

       .. index::
          pair: duration; months

       months
     - :ref:`integer <integer>`
     - 0
     - Number of months to add to the total duration
   * - .. _duration_years:

       .. index::
          pair: duration; years

       years
     - :ref:`integer <integer>`
     - 0
     - Number of years to add to the total duration


Example Date/Time Expressions
_____________________________


.. topic:: Satisfied if the current year is 2005

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

.. topic:: 9 a.m. to 6 p.m. Monday through Friday, or anytime Saturday

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
         </date_expression>
      </rule>

   .. note:: Because no time is specified with the above dates, 00:00:00 is
             implied. This means that the range includes all of 2005-03-01 but
             only the first second of 2005-04-01. You may wish to write ``end``
             as ``"2005-03-31T23:59:59"`` to avoid confusion.


.. index::
   single: rule; node attribute expression
   single: node attribute; rule expression
   pair: XML element; expression

.. _node_attribute_expressions:

Node Attribute Expressions
##########################

The ``expression`` element configures a rule condition based on the value of a
node attribute. It is allowed in rules in location constraints and in
``instance_attributes`` elements within ``bundle``, ``clone``, ``group``,
``op``, ``primitive``, and ``template`` elements.

.. list-table:: **Attributes of an expression Element**
   :class: longtable
   :widths: 1 1 3 5
   :header-rows: 1
   
   * - Name
     - Type
     - Default
     - Description
   
   * - .. _expression_id:
     
       .. index::
          pair: expression; id
        
       id
     - :ref:`id <id>`
     -
     - A unique name for this element (required)
   * - .. _expression_attribute:
     
       .. index::
          pair: expression; attribute
        
       attribute
     - :ref:`text <text>`
     -
     - Name of the node attribute to test (required)
   * - .. _expression_operation:
     
       .. index::
          pair: expression; operation
        
       operation
     - :ref:`enumeration <enumeration>`
     - 
     - The comparison to perform (required). Allowed values:
       
       * ``defined:`` The expression is satisfied if the node has the named
         attribute
       * ``not_defined:`` The expression is satisfied if the node does not have
         the named attribute
       * ``lt:`` The expression is satisfied if the node attribute value is
         less than the reference value
       * ``gt:`` The expression is satisfied if the node attribute value is
         greater than the reference value
       * ``lte:`` The expression is satisfied if the node attribute value is
         less than or equal to the reference value
       * ``gte:`` The expression is satisfied if the node attribute value is
         greater than or equal to the reference value
       * ``eq:`` The expression is satisfied if the node attribute value is
         equal to the reference value
       * ``ne:`` The expression is satisfied if the node attribute value is not
         equal to the reference value
   * - .. _expression_type:
     
       .. index::
          pair: expression; type
        
       type
     - :ref:`enumeration <enumeration>`
     - The default type for ``lt``, ``gt``, ``lte``, and ``gte`` operations is
       ``number`` if either value contains a decimal point character, or
       ``integer`` otherwise. The default type for all other operations is
       ``string``. If a numeric parse fails for either value, then the values
       are compared as type ``string``.
     - How to interpret values. Allowed values are ``string``, ``integer``
       *(since 2.0.5)*, ``number``, and ``version``. ``integer`` truncates
       floating-point values if necessary before performing a 64-bit integer
       comparison. ``number`` performs a double-precision floating-point
       comparison *(32-bit integer before 2.0.5)*.
   * - .. _expression_value:
     
       .. index::
          pair: expression; value
        
       value
     - :ref:`text <text>`
     -
     - Reference value to compare node attribute against (used only with, and
       required for, operations other than ``defined`` and ``not_defined``)
   * - .. _expression_value_source:
     
       .. index::
          pair: expression; value-source
        
       value-source
     - :ref:`enumeration <enumeration>`
     - ``literal``
     - How the reference value is obtained. Allowed values:
       
       * ``literal``: ``value`` contains the literal reference value to compare
       * ``param``: ``value`` contains the name of a resource parameter to
         compare (valid only in the context of a location constraint)
       * ``meta``: ``value`` is the name of a resource meta-attribute to
         compare (valid only in the context of a location constraint)

.. _node-attribute-expressions-special:

In addition to custom node attributes defined by the administrator, the cluster
defines special, built-in node attributes for each node that can also be used
in rule expressions.

.. list-table:: **Built-in Node Attributes**
   :class: longtable
   :widths: 1 4
   :header-rows: 1

   * - Name
     - Description
   * - #uname
     - :ref:`Node name <node_name>`
   * - #id
     - Node ID
   * - #kind
     - Node type (``cluster`` for cluster nodes, ``remote`` for Pacemaker
       Remote nodes created with the ``ocf:pacemaker:remote`` resource, and
       ``container`` for Pacemaker Remote guest nodes and bundle nodes)
   * - #is_dc
     - ``true`` if this node is the cluster's Designated Controller (DC),
       ``false`` otherwise
   * - #cluster-name
     - The value of the ``cluster-name`` cluster property, if set
   * - #site-name
     - The value of the ``site-name`` node attribute, if set, otherwise
       identical to ``#cluster-name``


.. _rsc_expression:

.. index::
   single: rule; resource expression
   single: resource; rule expression
   pair: XML element; rsc_expression

Resource Type Expressions
#########################

The ``rsc_expression`` element *(since 2.0.5)* configures a rule condition
based on the agent used for a resource. It is allowed in rules in a
``meta_attributes`` element within a ``rsc_defaults`` or ``op_defaults``
element.

.. list-table:: **Attributes of a rsc_expression Element**
   :class: longtable
   :widths: 1 1 1 4
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description
   * - .. _rsc_expression_id:

       .. index::
          pair: rsc_expression; id

       id
     - :ref:`id <id>`
     - 
     - A unique name for this element (required)
   * - .. _rsc_expression_class:

       .. index::
          pair: rsc_expression; class

       class
     - :ref:`text <text>`
     - 
     - If this is set, the expression is satisfied only if the resource's agent
       standard matches this value
   * - .. _rsc_expression_provider:

       .. index::
          pair: rsc_expression; provider

       provider
     - :ref:`text <text>`
     - 
     - If this is set, the expression is satisfied only if the resource's agent
       provider matches this value
   * - .. _rsc_expression_type:

       .. index::
          pair: rsc_expression; type

       type
     - :ref:`text <text>`
     - 
     - If this is set, the expression is satisfied only if the resource's agent
       type matches this value


Example Resource Type Expressions
_________________________________

.. topic:: Satisfied for ``ocf:heartbeat:IPaddr2`` resources

   .. code-block:: xml

      <rule id="rule1" score="INFINITY">
          <rsc_expression id="rule_expr1" class="ocf" provider="heartbeat" type="IPaddr2"/>
      </rule>

.. topic:: Satisfied for ``stonith:fence_xvm`` resources

   .. code-block:: xml

      <rule id="rule2" score="INFINITY">
          <rsc_expression id="rule_expr2" class="stonith" type="fence_xvm"/>
      </rule>


.. _op_expression:

.. index::
   single: rule; operation expression
   single: operation; rule expression
   pair: XML element; op_expression

Operation Type Expressions
##########################

The ``op_expression`` element *(since 2.0.5)* configures a rule condition based
on a resource operation name and interval. It is allowed in rules in a
``meta_attributes`` element within an ``op_defaults`` element.

.. list-table:: **Attributes of an op_expression Element**
   :class: longtable
   :widths: 1 1 1 4
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description
   * - .. _op_expression_id:

       .. index::
          pair: op_expression; id

       id
     - :ref:`id <id>`
     - 
     - A unique name for this element (required)
   * - .. _op_expression_name:

       .. index::
          pair: op_expression; name

       name
     - :ref:`text <text>`
     - 
     - The expression is satisfied only if the operation's name matches this
       value (required)
   * - .. _op_expression_interval:

       .. index::
          pair: op_expression; interval

       interval
     - :ref:`duration <duration>`
     - 
     - If this is set, the expression is satisfied only if the operation's
       interval matches this value


Example Operation Type Expressions
__________________________________

.. topic:: Expression is satisfied for all monitor actions

   .. code-block:: xml

      <rule id="rule1" score="INFINITY">
          <op_expression id="rule_expr1" name="monitor"/>
      </rule>

.. topic:: Expression is satisfied for all monitor actions with a 10-second interval

   .. code-block:: xml

      <rule id="rule2" score="INFINITY">
          <op_expression id="rule_expr2" name="monitor" interval="10s"/>
      </rule>


.. _location_rule:

.. index::
   pair: location constraint; rule

Using Rules to Determine Resource Location
##########################################

If a :ref:`location constraint <location-constraint>` contains a rule, the
cluster will apply the constraint to all nodes where the rule is satisfied.
This acts as if identical location constraints without rules were defined for
each of the nodes.

In the context of a location constraint, ``rule`` elements may take additional
attributes. These have an effect only when set for the constraint's top-level
``rule``; they are ignored if set on a subrule.

.. list-table:: **Extra Attributes of a rule Element in a Location Constraint**
   :class: longtable
   :widths: 2 2 1 5
   :header-rows: 1
   
   * - Name
     - Type
     - Default
     - Description
   
   * - .. _rule_role:
     
       .. index::
          pair: rule; role
        
       role
     - :ref:`enumeration <enumeration>`
     - ``Started``
     - If this is set in the constraint's top-level rule, the constraint acts
       as if ``role`` were set to this in the ``rsc_location`` element.

   * - .. _rule_score:
     
       .. index::
          pair: rule; score
        
       score
     - :ref:`score <score>`
     - 
     - If this is set in the constraint's top-level rule, the constraint acts
       as if ``score`` were set to this in the ``rsc_location`` element.
       Only one of ``score`` and ``score-attribute`` may be set.

   * - .. _rule_score_attribute:
     
       .. index::
          pair: rule; score-attribute
        
       score-attribute
     - :ref:`text <text>`
     - 
     - If this is set in the constraint's top-level rule, the constraint acts
       as if ``score`` were set to the value of this node attribute on each
       node where the rule is satisfied. Only one of ``score`` and
       ``score-attribute`` may be set.

Consider the following simple location constraint:

.. topic:: Prevent resource ``webserver`` from running on node ``node3``

   .. code-block:: xml

      <rsc_location id="ban-apache-on-node3" rsc="webserver"
                    score="-INFINITY" node="node3"/>

The same constraint can be written more verbosely using a rule:

.. topic:: Prevent resource ``webserver`` from running on node ``node3`` using a rule

   .. code-block:: xml

      <rsc_location id="ban-apache-on-node3" rsc="webserver">
          <rule id="ban-apache-rule" score="-INFINITY">
            <expression id="ban-apache-expr" attribute="#uname"
              operation="eq" value="node3"/>
          </rule>
      </rsc_location>

The advantage of using the expanded form is that one could add more expressions
(for example, limiting the constraint to certain days of the week).

Location Rules Based on Other Node Properties
_____________________________________________

The expanded form allows us to match node attributes other than its name. As an
example, consider this configuration of custom node attributes specifying each
node's CPU capacity:

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

We can use a rule to prevent a resource from running on underpowered machines:

.. topic:: Rule using a node attribute (to be used inside a location constraint)

   .. code-block:: xml

      <rule id="need-more-power-rule" score="-INFINITY">
         <expression id="need-more-power-expr" attribute="cpu_mips"
                     operation="lt" value="3000"/>
      </rule>

Using ``score-attribute`` Instead of ``score``
______________________________________________

When using ``score-attribute`` instead of ``score``, each node matched by the
rule has its score adjusted according to its value for the named node
attribute.

In the previous example, if the location constraint rule used
``score-attribute="cpu_mips"`` instead of ``score="-INFINITY"``, node
``c001n01`` would have its preference to run the resource increased by 1234
whereas node ``c001n02`` would have its preference increased by 5678.


.. _s-rsc-pattern-rules:

Specifying location scores using pattern submatches
___________________________________________________

Location constraints may use :ref:`rsc-pattern <s-rsc-pattern>` to apply the
constraint to all resources whose IDs match the given pattern. The pattern may
contain up to 9 submatches in parentheses, whose values may be used as ``%1``
through ``%9`` in a ``rule`` element's ``score-attribute`` or an ``expression``
element's ``attribute``.

For example, the following configuration excerpt gives the resources
**server-httpd** and **ip-httpd** a preference of 100 on node1 and 50 on node2,
and **ip-gateway** a preference of -100 on node1 and 200 on node2.

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


.. _option_rule:

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

* :ref:`Cluster options <cluster_options>` (as ``cluster_property_set``
  elements)
* :ref:`Node attributes <node_attributes>` (as ``instance_attributes`` or
  ``utilization`` elements inside a ``node`` element)
* :ref:`Resource options <resource_options>` (as ``utilization``,
  ``meta_attributes``, or ``instance_attributes`` elements inside a resource
  definition element or ``op`` , ``rsc_defaults``, ``op_defaults``, or
  ``template`` element)
* :ref:`Operation options <operation_properties>` (as ``meta_attributes``
  elements inside an ``op`` or ``op_defaults`` element)
* :ref:`Alert options <alerts>` (as ``instance_attributes`` or
  ``meta_attributes`` elements inside an ``alert`` or ``recipient`` element)


Using Rules to Control Resource Options
_______________________________________

Often some cluster nodes will be different from their peers. Sometimes,
these differences (for example, the location of a binary, or the names of
network interfaces) require resources to be configured differently depending
on the machine they're hosted on.

By defining multiple ``instance_attributes`` elements for the resource and
adding a rule to each, we can easily handle these special cases.

In the example below, ``mySpecialRsc`` will use eth1 and port 9999 when run on
node1, eth2 and port 8888 on node2 and default to eth0 and port 9999 for all
other nodes.

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

Multiple ``instance_attributes`` elements are evaluated from highest score to
lowest. If not supplied, the score defaults to zero. Objects with equal scores
are processed in their listed order. If an ``instance_attributes`` object has
no rule or a satisfied ``rule``, then for any parameter the resource does not
yet have a value for, the resource will use the value defined by the
``instance_attributes``.

For example, given the configuration above, if the resource is placed on
``node1``:

* ``special-node1`` has the highest score (3) and so is evaluated first; its
  rule is satisfied, so ``interface`` is set to ``eth1``.
* ``special-node2`` is evaluated next with score 2, but its rule is not
  satisfied, so it is ignored.
* ``defaults`` is evaluated last with score 1, and has no rule, so its values
  are examined; ``interface`` is already defined, so the value here is not
  used, but ``port`` is not yet defined, so ``port`` is set to ``9999``.

Using Rules to Control Resource Defaults
________________________________________

Rules can be used for resource and operation defaults.

The following example illustrates how to set a different
``resource-stickiness`` value during and outside work hours. This allows
resources to automatically move back to their most preferred hosts, but at a
time that (in theory) does not interfere with business activities.

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

``rsc_expression`` is valid within both ``rsc_defaults`` and ``op_defaults``;
``op_expression`` is valid only within ``op_defaults``.

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
