""" CIB XML generator for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = [ "Alerts", "Clone", "Expression", "FencingTopology", "Group", "Nodes", "OpDefaults", "Option", "Resource", "Rule" ]
__copyright__ = "Copyright 2008-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"


def key_val_string(**kwargs):
    """ Given keyword arguments as key=value pairs, construct a single string
        containing all those pairs separated by spaces.  This is suitable for
        using in an XML element as a list of its attributes.

        Any pairs that have value=None will be skipped.

        Note that a dictionary can be passed to this function instead of kwargs
        by using a construction like:

        key_val_string(**{"a": 1, "b": 2})
    """

    retval = ""

    for (k, v) in kwargs.items():
        if v is None:
            continue

        retval += ' %s="%s"' % (k, v)

    return retval


def element(element_name, **kwargs):
    """ Create an XML element string with the given element_name and attributes.
        This element does not support having any children, so it will be closed
        on the same line.  The attributes are processed by key_val_string.
    """

    return "<%s %s/>" % (element_name, key_val_string(**kwargs))


def containing_element(element_name, inner, **kwargs):
    """ Like element, but surrounds some child text passed by the inner
        parameter.
    """

    attrs = key_val_string(**kwargs)
    return "<%s %s>%s</%s>" % (element_name, attrs, inner, element_name)


class XmlBase:
    def __init__(self, factory, tag, _id, **kwargs):
        self._children = []
        self._factory = factory
        self._kwargs = kwargs
        self._tag = tag

        self.name = _id

    def __repr__(self):
        return "%s-%s" % (self._tag, self.name)

    def add_child(self, child):
        self._children.append(child)

    def __setitem__(self, key, value):
        if value:
            self._kwargs[key] = value
        else:
            self._kwargs.pop(key, None)

    def show(self):
        text = '''<%s''' % self._tag
        if self.name:
            text += ''' id="%s"''' % self.name

        text += key_val_string(**self._kwargs)

        if not self._children:
            text += '''/>'''
            return text

        text += '''>'''

        for c in self._children:
            text += c.show()

        text += '''</%s>''' % self._tag
        return text

    def _run(self, operation, xml, section, options=""):
        if self.name:
            label = self.name
        else:
            label = "<%s>" % self._tag

        self._factory.debug("Writing out %s" % label)

        fixed  = "HOME=/root CIB_file=%s" % self._factory.tmpfile
        fixed += " cibadmin --%s --scope %s %s --xml-text '%s'" % (operation, section, options, xml)

        (rc, _) = self._factory.rsh(self._factory.target, fixed)
        if rc != 0:
            raise RuntimeError("Configure call failed: %s" % fixed)


class InstanceAttributes(XmlBase):
    """ Create an <instance_attributes> section with name-value pairs """

    def __init__(self, factory, name, attrs):
        XmlBase.__init__(self, factory, "instance_attributes", name)

        # Create an <nvpair> for each attribute
        for (attr, value) in attrs.items():
            self.add_child(XmlBase(factory, "nvpair", "%s-%s" % (name, attr),
                                   name=attr, value=value))


class Node(XmlBase):
    """ Create a <node> section with node attributes for one node """

    def __init__(self, factory, node_name, node_id, node_attrs):
        XmlBase.__init__(self, factory, "node", node_id, uname=node_name)
        self.add_child(InstanceAttributes(factory, "%s-1" % node_name, node_attrs))


class Nodes(XmlBase):
    """ Create a <nodes> section """

    def __init__(self, factory):
        XmlBase.__init__(self, factory, "nodes", None)

    def add_node(self, node_name, node_id, node_attrs):
        self.add_child(Node(self._factory, node_name, node_id, node_attrs))

    def commit(self):
        self._run("modify", self.show(), "configuration", "--allow-create")


class FencingTopology(XmlBase):
    def __init__(self, factory):
        XmlBase.__init__(self, factory, "fencing-topology", None)

    def level(self, index, target, devices, target_attr=None, target_value=None):
        # Generate XML ID (sanitizing target-by-attribute levels)

        if target:
            xml_id = "cts-%s.%d" % (target, index)
            self.add_child(XmlBase(self._factory, "fencing-level", xml_id, target=target, index=index, devices=devices))

        else:
            xml_id = "%s-%s.%d" % (target_attr, target_value, index)
            child = XmlBase(self._factory, "fencing-level", xml_id, index=index, devices=devices)
            child["target-attribute"]=target_attr
            child["target-value"]=target_value
            self.add_child(child)

    def commit(self):
        self._run("create", self.show(), "configuration", "--allow-create")


class Option(XmlBase):
    def __init__(self, factory, section="cib-bootstrap-options"):
        XmlBase.__init__(self, factory, "cluster_property_set", section)

    def __setitem__(self, key, value):
        self.add_child(XmlBase(self._factory, "nvpair", "cts-%s" % key, name=key, value=value))

    def commit(self):
        self._run("modify", self.show(), "crm_config", "--allow-create")


class OpDefaults(XmlBase):
    def __init__(self, factory):
        XmlBase.__init__(self, factory, "op_defaults", None)
        self.meta = XmlBase(self._factory, "meta_attributes", "cts-op_defaults-meta")
        self.add_child(self.meta)

    def __setitem__(self, key, value):
        self.meta.add_child(XmlBase(self._factory, "nvpair", "cts-op_defaults-%s" % key, name=key, value=value))

    def commit(self):
        self._run("modify", self.show(), "configuration", "--allow-create")


class Alerts(XmlBase):
    def __init__(self, factory):
        XmlBase.__init__(self, factory, "alerts", None)
        self._alert_count = 0

    def add_alert(self, path, recipient):
        self._alert_count += 1
        alert = XmlBase(self._factory, "alert", "alert-%d" % self._alert_count,
                        path=path)
        recipient1 = XmlBase(self._factory, "recipient",
                             "alert-%d-recipient-1" % self._alert_count,
                             value=recipient)
        alert.add_child(recipient1)
        self.add_child(alert)

    def commit(self):
        self._run("modify", self.show(), "configuration", "--allow-create")


class Expression(XmlBase):
    def __init__(self, factory, name, attr, op, value=None):
        XmlBase.__init__(self, factory, "expression", name, attribute=attr, operation=op)
        if value:
            self["value"] = value


class Rule(XmlBase):
    def __init__(self, factory, name, score, op="and", expr=None):
        XmlBase.__init__(self, factory, "rule", "%s" % name)

        self["boolean-op"] = op
        self["score"] = score

        if expr:
            self.add_child(expr)


class Resource(XmlBase):
    def __init__(self, factory, name, rtype, standard, provider=None):
        XmlBase.__init__(self, factory, "native", name)

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
        self._add_param(key, value)

    def add_op(self, name, interval, **kwargs):
        self._op.append(XmlBase(self._factory, "op", "%s-%s" % (name, interval),
                                name=name, interval=interval, **kwargs))

    def _add_param(self, name, value):
        self._param[name] = value

    def add_meta(self, name, value):
        self._meta[name] = value

    def prefer(self, node, score="INFINITY", rule=None):
        if not rule:
            rule = Rule(self._factory, "prefer-%s-r" % node, score,
                        expr=Expression(self._factory, "prefer-%s-e" % node, "#uname", "eq", node))

        self._scores[node] = rule

    def after(self, resource, kind="Mandatory", first="start", then="start", **kwargs):
        kargs = kwargs.copy()
        kargs["kind"] = kind

        if then:
            kargs["first-action"] = "start"
            kargs["then-action"] = then

        if first:
            kargs["first-action"] = first

        self._needs[resource] = kargs

    def colocate(self, resource, score="INFINITY", role=None, withrole=None, **kwargs):
        kargs = kwargs.copy()
        kargs["score"] = score

        if role:
            kargs["rsc-role"] = role

        if withrole:
            kargs["with-rsc-role"] = withrole

        self._coloc[resource] = kargs

    def _constraints(self):
        text = "<constraints>"

        for (k, v) in self._scores.items():
            attrs = {"id": "prefer-%s" % k, "rsc": self.name}
            text += containing_element("rsc_location", v.show(), **attrs)

        for (k, kargs) in self._needs.items():
            attrs = {"id": "%s-after-%s" % (self.name, k), "first": k, "then": self.name}
            text += element("rsc_order", **attrs, **kargs)

        for (k, kargs) in self._coloc.items():
            attrs = {"id": "%s-with-%s" % (self.name, k), "rsc": self.name, "with-rsc": k}
            text += element("rsc_colocation", **attrs)

        text += "</constraints>"
        return text

    def show(self):
        text = '''<primitive id="%s" class="%s" type="%s"''' % (self.name, self._standard, self._rtype)

        if self._provider:
            text += ''' provider="%s"''' % self._provider

        text += '''>'''

        if len(self._meta) > 0:
            nvpairs = ""
            for (p, v) in self._meta.items():
                attrs = {"id": "%s-%s" % (self.name, p), "name": p, "value": v}
                nvpairs += element("nvpair", **attrs)

            text += containing_element("meta_attributes", nvpairs,
                                       id="%s-meta" % self.name)

        if len(self._param) > 0:
            nvpairs = ""
            for (p, v) in self._param.items():
                attrs = {"id": "%s-%s" % (self.name, p), "name": p, "value": v}
                nvpairs += element("nvpair", **attrs)

            text += containing_element("instance_attributes", nvpairs,
                                       id="%s-params" % self.name)

        if len(self._op) > 0:
            text += '''<operations>'''

            for o in self._op:
                key = o.name
                o.name = "%s-%s" % (self.name, key)
                text += o.show()
                o.name = key

            text += '''</operations>'''

        text += '''</primitive>'''
        return text

    def commit(self):
        self._run("create", self.show(), "resources")
        self._run("modify", self._constraints(), "constraints")


class Group(Resource):
    def __init__(self, factory, name):
        Resource.__init__(self, factory, name, None, None)
        self.tag = "group"

    def __setitem__(self, key, value):
        self.add_meta(key, value)

    def show(self):
        text = '''<%s id="%s">''' % (self.tag, self.name)

        if len(self._meta) > 0:
            nvpairs = ""
            for (p, v) in self._meta.items():
                attrs = {"id": "%s-%s" % (self.name, p), "name": p, "value": v}
                nvpairs += element("nvpair", **attrs)

            text += containing_element("meta_attributes", nvpairs,
                                       id="%s-meta" % self.name)

        for c in self._children:
            text += c.show()

        text += '''</%s>''' % self.tag
        return text


class Clone(Group):
    def __init__(self, factory, name, child=None):
        Group.__init__(self, factory, name)
        self.tag = "clone"

        if child:
            self.add_child(child)

    def add_child(self, child):
        if not self._children:
            self._children.append(child)
        else:
            self._factory.log("Clones can only have a single child. Ignoring %s" % child.name)
