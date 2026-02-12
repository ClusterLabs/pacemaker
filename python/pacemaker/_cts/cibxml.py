"""CIB XML generator for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = [
    "Alerts",
    "Clone",
    "Expression",
    "FencingTopology",
    "Group",
    "Nodes",
    "OpDefaults",
    "Option",
    "Resource",
    "Rule",
]
__copyright__ = "Copyright 2008-2025 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"


def key_val_string(**kwargs):
    """
    Construct a string from kwargs containing key=value pairs separated by spaces.

    This is suitable for using in an XML element as a list of its attributes.
    Any pairs that have value=None will be skipped.

    Note that a dictionary can be passed to this function instead of kwargs
    by using a construction like:

        key_val_string(**{"a": 1, "b": 2})
    """
    retval = ""

    for (k, v) in kwargs.items():
        if v is None:
            continue

        retval += f' {k}="{v}"'

    return retval


def element(element_name, **kwargs):
    """
    Create an XML element string with the given element_name and attributes.

    This element does not support having any children, so it will be closed
    on the same line.  The attributes are processed by key_val_string.
    """
    return f"<{element_name} {key_val_string(**kwargs)}/>"


def containing_element(element_name, inner, **kwargs):
    """Like element, but surrounds some child text passed by the inner parameter."""
    attrs = key_val_string(**kwargs)
    return f"<{element_name} {attrs}>{inner}</{element_name}>"


class XmlBase:
    """
    A base class for deriving all kinds of XML sections in the CIB.

    This class contains only the most basic operations common to all sections.
    It is up to subclasses to provide most behavior.

    Note that subclasses of this base class often have different sets of
    arguments to their __init__ methods.  In general this is not a great
    practice, however it is so thoroughly used in these classes that trying
    to straighten it out is likely to cause more bugs than just leaving it
    alone for now.
    """

    def __init__(self, factory, tag, _id, **kwargs):
        """
        Create a new XmlBase instance.

        Arguments:
        factory -- A ConfigFactory instance
        tag     -- The XML element's start and end tag
        _id     -- A unique name for the element
        kwargs  -- Any additional key/value pairs that should be added to
                   this element as attributes
        """
        self._children = []
        self._factory = factory
        self._kwargs = kwargs
        self._tag = tag

        self.name = _id

    def __repr__(self):
        """Return a short string description of this XML section."""
        return f"{self._tag}-{self.name}"

    def add_child(self, child):
        """Add an XML section as a child of this one."""
        self._children.append(child)

    def __setitem__(self, key, value):
        """
        Add a key/value pair to this element.

        The resulting pair becomes an XML attribute.  If value is None, remove
        the key.
        """
        if value:
            self._kwargs[key] = value
        else:
            self._kwargs.pop(key, None)

    def show(self):
        """Recursively return a string representation of this XML section."""
        text = f"<{self._tag}"
        if self.name:
            text += f' id="{self.name}"'

        text += key_val_string(**self._kwargs)

        if not self._children:
            text += '''/>'''
            return text

        text += '''>'''

        for c in self._children:
            text += c.show()

        text += f"</{self._tag}>"
        return text

    def _run(self, operation, xml, section, options=""):
        """
        Update the CIB on the cluster to include this XML section.

        Arguments:
        operation -- Whether this update is a "create" or "modify" operation
        xml       -- The XML to update the CIB with, typically the result
                     of calling show
        section   -- Which section of the CIB this update applies to (see
                     the --scope argument to cibadmin for allowed values)
        options   -- Extra options to pass to cibadmin
        """
        if self.name:
            label = self.name
        else:
            label = f"<{self._tag}>"

        self._factory.debug(f"Writing out {label}")

        fixed = f"HOME=/root CIB_file={self._factory.tmpfile}"
        fixed += f" cibadmin --{operation} --scope {section} {options} --xml-text '{xml}'"

        (rc, _) = self._factory.rsh.call(self._factory.target, fixed)
        if rc != 0:
            raise RuntimeError(f"Configure call failed: {fixed}")


class InstanceAttributes(XmlBase):
    """Create an <instance_attributes> XML section with key/value pairs."""

    def __init__(self, factory, _id, attrs):
        """
        Create a new InstanceAttributes instance.

        Arguments:
        factory -- A ConfigFactory instance
        _id     -- A unique name for the element
        attrs   -- Key/value pairs to add as nvpair child elements
        """
        XmlBase.__init__(self, factory, "instance_attributes", _id)

        # Create an <nvpair> for each attribute
        for (attr, value) in attrs.items():
            self.add_child(XmlBase(factory, "nvpair", f"{_id}-{attr}",
                                   name=attr, value=value))


class Node(XmlBase):
    """Create a <node> XML section for a single node, complete with node attributes."""

    def __init__(self, factory, node_name, node_id, node_attrs):
        """
        Create a new Node instance.

        Arguments:
        factory    -- A ConfigFactory instance
        node_name  -- The value of the uname attribute for this node
        node_id    -- A unique name for the element
        node_attrs -- Additional key/value pairs to set as instance
                      attributes for this node
        """
        XmlBase.__init__(self, factory, "node", node_id, uname=node_name)
        self.add_child(InstanceAttributes(factory, f"{node_name}-1", node_attrs))


class Nodes(XmlBase):
    """Create a <nodes> XML section containing multiple Node instances as children."""

    def __init__(self, factory):
        """
        Create a new Nodes instance.

        Arguments:
        factory -- A ConfigFactory instance
        """
        XmlBase.__init__(self, factory, "nodes", None)

    def add_node(self, node_name, node_id, node_attrs):
        """
        Add a child node element.

        Arguments:
        node_name  -- The value of the uname attribute for this node
        node_id    -- A unique name for the element
        node_attrs -- Additional key/value pairs to set as instance
                      attributes for this node
        """
        self.add_child(Node(self._factory, node_name, node_id, node_attrs))

    def commit(self):
        """Modify the CIB on the cluster to include this XML section."""
        self._run("modify", self.show(), "configuration", "--allow-create")


class FencingTopology(XmlBase):
    """Create a <fencing-topology> XML section describing how fencing is configured in the cluster."""

    def __init__(self, factory):
        """
        Create a new FencingTopology instance.

        Arguments:
        factory -- A ConfigFactory instance
        """
        XmlBase.__init__(self, factory, "fencing-topology", None)

    def level(self, index, target, devices, target_attr=None, target_value=None):
        """
        Generate a <fencing-level> XML element.

        index        -- The order in which to attempt fencing-levels
                        (1 through 9).  Levels are attempted in ascending
                        order until one succeeds.
        target       -- The name of a single node to which this level applies
        devices      -- A list of devices that must all be tried for this
                        level
        target_attr  -- The name of a node attribute that is set for nodes
                        to which this level applies
        target_value -- The value of a node attribute that is set for nodes
                        to which this level applies
        """
        if target:
            xml_id = f"cts-{target}.{index}"
            self.add_child(XmlBase(self._factory, "fencing-level", xml_id, target=target, index=index, devices=devices))

        else:
            xml_id = f"{target_attr}-{target_value}.{index}"
            child = XmlBase(self._factory, "fencing-level", xml_id, index=index, devices=devices)
            child["target-attribute"] = target_attr
            child["target-value"] = target_value
            self.add_child(child)

    def commit(self):
        """Create this XML section in the CIB."""
        self._run("create", self.show(), "configuration", "--allow-create")


class Option(XmlBase):
    """Create a <cluster_property_set> XML section of key/value pairs for cluster-wide configuration settings."""

    def __init__(self, factory, _id="cib-bootstrap-options"):
        """
        Create a new Option instance.

        Arguments:
        factory -- A ConfigFactory instance
        _id     -- A unique name for the element
        """
        XmlBase.__init__(self, factory, "cluster_property_set", _id)

    def __setitem__(self, key, value):
        """Add a child nvpair element containing the given key/value pair."""
        self.add_child(XmlBase(self._factory, "nvpair", f"cts-{key}", name=key, value=value))

    def commit(self):
        """Modify the CIB on the cluster to include this XML section."""
        self._run("modify", self.show(), "crm_config", "--allow-create")


class OpDefaults(XmlBase):
    """Create a <cts-op_defaults-meta> XML section of key/value pairs for operation default settings."""

    def __init__(self, factory):
        """
        Create a new OpDefaults instance.

        Arguments:
        factory -- A ConfigFactory instance
        """
        XmlBase.__init__(self, factory, "op_defaults", None)
        self.meta = XmlBase(self._factory, "meta_attributes", "cts-op_defaults-meta")
        self.add_child(self.meta)

    def __setitem__(self, key, value):
        """Add a child nvpair meta_attribute element containing the given key/value pair."""
        self.meta.add_child(XmlBase(self._factory, "nvpair", f"cts-op_defaults-{key}", name=key, value=value))

    def commit(self):
        """Modify the CIB on the cluster to include this XML section."""
        self._run("modify", self.show(), "configuration", "--allow-create")


class Alerts(XmlBase):
    """Create an <alerts> XML section."""

    def __init__(self, factory):
        """
        Create a new Alerts instance.

        Arguments:
        factory -- A ConfigFactory instance
        """
        XmlBase.__init__(self, factory, "alerts", None)
        self._alert_count = 0

    def add_alert(self, path, recipient):
        """
        Create a new alert as a child of this XML section.

        Arguments:
        path      -- The path to a script to be called when a cluster
                     event occurs
        recipient -- An environment variable to be passed to the script
        """
        self._alert_count += 1
        alert = XmlBase(self._factory, "alert", f"alert-{self._alert_count}",
                        path=path)
        recipient1 = XmlBase(self._factory, "recipient",
                             f"alert-{self._alert_count}-recipient-1",
                             value=recipient)
        alert.add_child(recipient1)
        self.add_child(alert)

    def commit(self):
        """Modify the CIB on the cluster to include this XML section."""
        self._run("modify", self.show(), "configuration", "--allow-create")


class Expression(XmlBase):
    """Create an <expression> XML element as part of some constraint rule."""

    def __init__(self, factory, _id, attr, op, value=None):
        """
        Create a new Expression instance.

        Arguments:
        factory -- A ConfigFactory instance
        _id     -- A unique name for the element
        attr    -- The attribute to be tested
        op      -- The comparison to perform ("lt", "eq", "defined", etc.)
        value   -- Value for comparison (can be None for "defined" and
                   "not_defined" operations)
        """
        XmlBase.__init__(self, factory, "expression", _id, attribute=attr, operation=op)
        if value:
            self["value"] = value


class Rule(XmlBase):
    """Create a <rule> XML section consisting of one or more expressions, as part of some constraint."""

    def __init__(self, factory, _id, score, op="and", expr=None):
        """
        Create a new Rule instance.

        Arguments:
        factory -- A ConfigFactory instance
        _id     -- A unique name for the element
        score   -- If this rule is used in a location constraint and
                   evaluates to true, apply this score to the constraint
        op      -- If this rule contains more than one expression, use this
                   boolean op when evaluating
        expr    -- An Expression instance that can be added to this Rule
                   when it is created
        """
        XmlBase.__init__(self, factory, "rule", _id)

        self["boolean-op"] = op
        self["score"] = score

        if expr:
            self.add_child(expr)


class Resource(XmlBase):
    """
    A base class that creates all kinds of <resource> XML sections.

    These sections fully describe a single cluster resource.  This defaults to
    primitive resources, but subclasses can create other types.
    """

    def __init__(self, factory, _id, rtype, standard, provider=None):
        """
        Create a new Resource instance.

        Arguments:
        factory  -- A ConfigFactory instance
        _id      -- A unique name for the element
        rtype    -- The name of the resource agent
        standard -- The standard the resource agent follows ("ocf",
                    "systemd", etc.)
        provider -- The vendor providing the resource agent
        """
        XmlBase.__init__(self, factory, "native", _id)

        self._provider = provider
        self._rtype = rtype
        self._standard = standard

        self._meta = {}
        self._op = []
        self._param = {}

        self._coloc = {}
        self._needs = {}
        self._scores = {}

        if self._standard == "ocf" and not provider:
            self._provider = "heartbeat"
        elif self._standard == "lsb":
            self._provider = None

    def __setitem__(self, key, value):
        """Add a child nvpair element containing the given key/value pair as an instance attribute."""
        self._add_param(key, value)

    def add_op(self, _id, interval, **kwargs):
        """
        Add an operation child XML element to this resource.

        Arguments:
        _id      -- A unique name for the element.  Also, the action to
                    perform ("monitor", "start", "stop", etc.)
        interval -- How frequently (in seconds) to perform the operation
        kwargs   -- Any additional key/value pairs that should be added to
                    this element as attributes
        """
        self._op.append(XmlBase(self._factory, "op", f"{_id}-{interval}",
                                name=_id, interval=interval, **kwargs))

    def _add_param(self, name, value):
        """Add a child nvpair element containing the given key/value pair as an instance attribute."""
        self._param[name] = value

    def add_meta(self, name, value):
        """Add a child nvpair element containing the given key/value pair as a meta attribute."""
        self._meta[name] = value

    def prefer(self, node, score="INFINITY", rule=None):
        """
        Add a location constraint where this resource prefers some node.

        Arguments:
        node  -- The name of the node to prefer
        score -- Apply this score to the location constraint
        rule  -- A Rule instance to use in creating this constraint, instead
                 of creating a new rule
        """
        if not rule:
            rule = Rule(self._factory, f"prefer-{node}-r", score,
                        expr=Expression(self._factory, f"prefer-{node}-e", "#uname", "eq", node))

        self._scores[node] = rule

    def after(self, resource, kind="Mandatory", first="start", then="start", **kwargs):
        """
        Create an ordering constraint between this resource and some other.

        Arguments:
        resource -- The name of the dependent resource
        kind     -- How to enforce the constraint ("mandatory", "optional",
                    "serialize")
        first    -- The action that this resource must complete before the
                    then-action can be initiated for the dependent resource
                    ("start", "stop", "promote", "demote")
        then     -- The action that the dependent resource can execute only
                    after the first-action has completed (same values as
                    first)
        kwargs   -- Any additional key/value pairs that should be added to
                    this element as attributes
        """
        kargs = kwargs.copy()
        kargs["kind"] = kind

        if then:
            kargs["first-action"] = "start"
            kargs["then-action"] = then

        if first:
            kargs["first-action"] = first

        self._needs[resource] = kargs

    def colocate(self, resource, score="INFINITY", role=None, withrole=None, **kwargs):
        """
        Create a colocation constraint between this resource and some other.

        Arguments:
        resource -- The name of the resource that should be located relative
                    this one
        score    -- Apply this score to the colocation constraint
        role     -- Apply this colocation constraint only to promotable clones
                    in this role ("started", "promoted", "unpromoted")
        withrole -- Apply this colocation constraint only to with-rsc promotable
                    clones in this role
        kwargs   -- Any additional key/value pairs that should be added to
                    this element as attributes
        """
        kargs = kwargs.copy()
        kargs["score"] = score

        if role:
            kargs["rsc-role"] = role

        if withrole:
            kargs["with-rsc-role"] = withrole

        self._coloc[resource] = kargs

    def _constraints(self):
        """Generate a <constraints> XML section containing all previously added ordering and colocation constraints."""
        text = "<constraints>"

        for (k, v) in self._scores.items():
            attrs = {"id": f"prefer-{k}", "rsc": self.name}
            text += containing_element("rsc_location", v.show(), **attrs)

        for (k, kargs) in self._needs.items():
            attrs = {"id": f"{self.name}-after-{k}", "first": k, "then": self.name}
            text += element("rsc_order", **attrs, **kargs)

        for (k, kargs) in self._coloc.items():
            attrs = {"id": f"{self.name}-with-{k}", "rsc": self.name, "with-rsc": k}
            text += element("rsc_colocation", **attrs)

        text += "</constraints>"
        return text

    def show(self):
        """Recursively return a string representation of this XML section."""
        text = f'<primitive id="{self.name}" class="{self._standard}" type="{self._rtype}"'

        if self._provider:
            text += f' provider="{self._provider}"'

        text += '''>'''

        if self._meta:
            nvpairs = ""
            for (p, v) in self._meta.items():
                attrs = {"id": f"{self.name}-{p}", "name": p, "value": v}
                nvpairs += element("nvpair", **attrs)

            text += containing_element("meta_attributes", nvpairs,
                                       id=f"{self.name}-meta")

        if self._param:
            nvpairs = ""
            for (p, v) in self._param.items():
                attrs = {"id": f"{self.name}-{p}", "name": p, "value": v}
                nvpairs += element("nvpair", **attrs)

            text += containing_element("instance_attributes", nvpairs,
                                       id=f"{self.name}-params")

        if self._op:
            text += '''<operations>'''

            for o in self._op:
                key = o.name
                o.name = f"{self.name}-{key}"
                text += o.show()
                o.name = key

            text += '''</operations>'''

        text += '''</primitive>'''
        return text

    def commit(self):
        """Modify the CIB on the cluster to include this XML section."""
        self._run("create", self.show(), "resources")
        self._run("modify", self._constraints(), "constraints")


class Group(Resource):
    """
    A specialized Resource subclass that creates a <group> XML section.

    This section describes a single group resource consisting of multiple child
    primitive resources.
    """

    def __init__(self, factory, _id):
        """
        Create a new Group instance.

        Arguments:
        factory -- A ConfigFactory instance
        _id     -- A unique name for the element
        """
        Resource.__init__(self, factory, _id, None, None)
        self.tag = "group"

    def __setitem__(self, key, value):
        """Add a child nvpair element containing the given key/value pair as an instance attribute."""
        self.add_meta(key, value)

    def show(self):
        """Recursively return a string representation of this XML section."""
        text = f'<{self.tag} id="{self.name}">'

        if len(self._meta) > 0:
            nvpairs = ""
            for (p, v) in self._meta.items():
                attrs = {"id": f"{self.name}-{p}", "name": p, "value": v}
                nvpairs += element("nvpair", **attrs)

            text += containing_element("meta_attributes", nvpairs,
                                       id=f"{self.name}-meta")

        for c in self._children:
            text += c.show()

        text += f"</{self.tag}>"
        return text


class Clone(Group):
    """
    A specialized Group subclass that creates a <clone> XML section.

    This section describes a clone resource containing multiple instances of a
    single primitive resource.
    """

    def __init__(self, factory, _id, child=None):
        """
        Create a new Clone instance.

        Arguments:
        factory -- A ConfigFactory instance
        _id     -- A unique name for the element
        child   -- A Resource instance that can be added to this Clone
                   when it is created.  Alternately, use add_child later.
                   Note that a Clone may only have one child.
        """
        Group.__init__(self, factory, _id)
        self.tag = "clone"

        if child:
            self.add_child(child)

    def add_child(self, child):
        """
        Add the given resource as a child of this Clone.

        Note that a Clone resource only supports one child at a time.
        """
        if not self._children:
            self._children.append(child)
        else:
            self._factory.log(f"Clones can only have a single child. Ignoring {child.name}")
