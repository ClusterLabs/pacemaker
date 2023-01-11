""" CIB XML generator for Pacemaker's Cluster Test Suite (CTS)
"""

__copyright__ = "Copyright 2008-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import sys

from cts.CIB     import CibBase


class XmlBase(CibBase):
    def __init__(self, Factory, tag, _id, **kwargs):
        CibBase.__init__(self, Factory, tag, _id, **kwargs)

    def show(self):
        text = '''<%s''' % self.tag
        if self.name:
            text += ''' id="%s"''' % (self.name)
        for k in list(self.kwargs.keys()):
            text += ''' %s="%s"''' % (k, self.kwargs[k])

        if not self.children:
            text += '''/>'''
            return text

        text += '''>'''

        for c in self.children:
            text += c.show()

        text += '''</%s>''' % self.tag
        return text

    def _run(self, operation, xml, section="all", options=""):
        if self.name:
            label = self.name
        else:
            label = "<%s>" % self.tag
        self.Factory.debug("Writing out %s" % label)
        fixed  = "HOME=/root CIB_file="+self.Factory.tmpfile
        fixed += " cibadmin --%s --scope %s %s --xml-text '%s'" % (operation, section, options, xml)
        rc = self.Factory.rsh(self.Factory.target, fixed)
        if rc != 0:
            self.Factory.log("Configure call failed: "+fixed)
            sys.exit(1)


class InstanceAttributes(XmlBase):
    """ Create an <instance_attributes> section with name-value pairs """

    def __init__(self, Factory, name, attrs):
        XmlBase.__init__(self, Factory, "instance_attributes", name)

        # Create an <nvpair> for each attribute
        for (attr, value) in list(attrs.items()):
            self.add_child(XmlBase(Factory, "nvpair", "%s-%s" % (name, attr),
                name=attr, value=value))


class Node(XmlBase):
    """ Create a <node> section with node attributes for one node """

    def __init__(self, Factory, node_name, node_id, node_attrs):
        XmlBase.__init__(self, Factory, "node", node_id, uname=node_name)
        self.add_child(InstanceAttributes(Factory, "%s-1" % node_name, node_attrs))


class Nodes(XmlBase):
    """ Create a <nodes> section """

    def __init__(self, Factory):
        XmlBase.__init__(self, Factory, "nodes", None)

    def add_node(self, node_name, node_id, node_attrs):
        self.add_child(Node(self.Factory, node_name, node_id, node_attrs))

    def commit(self):
        self._run("modify", self.show(), "configuration", "--allow-create")


class FencingTopology(XmlBase):
    def __init__(self, Factory):
        XmlBase.__init__(self, Factory, "fencing-topology", None)

    def level(self, index, target, devices, target_attr=None, target_value=None):
        # Generate XML ID (sanitizing target-by-attribute levels)

        if target:
            xml_id = "cts-%s.%d" % (target, index)
            self.add_child(XmlBase(self.Factory, "fencing-level", xml_id, target=target, index=index, devices=devices))

        else:
            xml_id = "%s-%s.%d" % (target_attr, target_value, index)
            child = XmlBase(self.Factory, "fencing-level", xml_id, index=index, devices=devices)
            child["target-attribute"]=target_attr
            child["target-value"]=target_value
            self.add_child(child)

    def commit(self):
        self._run("create", self.show(), "configuration", "--allow-create")


class Option(XmlBase):
    def __init__(self, Factory, section="cib-bootstrap-options"):
        XmlBase.__init__(self, Factory, "cluster_property_set", section)

    def __setitem__(self, key, value):
        self.add_child(XmlBase(self.Factory, "nvpair", "cts-%s" % key, name=key, value=value))

    def commit(self):
        self._run("modify", self.show(), "crm_config", "--allow-create")


class OpDefaults(XmlBase):
    def __init__(self, Factory):
        XmlBase.__init__(self, Factory, "op_defaults", None)
        self.meta = XmlBase(self.Factory, "meta_attributes", "cts-op_defaults-meta")
        self.add_child(self.meta)

    def __setitem__(self, key, value):
        self.meta.add_child(XmlBase(self.Factory, "nvpair", "cts-op_defaults-%s" % key, name=key, value=value))

    def commit(self):
        self._run("modify", self.show(), "configuration", "--allow-create")


class Alerts(XmlBase):
    def __init__(self, Factory):
        XmlBase.__init__(self, Factory, "alerts", None)
        self.alert_count = 0

    def add_alert(self, path, recipient):
        self.alert_count = self.alert_count + 1
        alert = XmlBase(self.Factory, "alert", "alert-%d" % self.alert_count,
                        path=path)
        recipient1 = XmlBase(self.Factory, "recipient",
                             "alert-%d-recipient-1" % self.alert_count,
                             value=recipient)
        alert.add_child(recipient1)
        self.add_child(alert)

    def commit(self):
        self._run("modify", self.show(), "configuration", "--allow-create")


class Expression(XmlBase):
    def __init__(self, Factory, name, attr, op, value=None):
        XmlBase.__init__(self, Factory, "expression", name, attribute=attr, operation=op)
        if value:
            self["value"] = value


class Rule(XmlBase):
    def __init__(self, Factory, name, score, op="and", expr=None):
        XmlBase.__init__(self, Factory, "rule", "%s" % name)
        self["boolean-op"] = op
        self["score"] = score
        if expr:
            self.add_child(expr)


class Resource(XmlBase):
    def __init__(self, Factory, name, rtype, standard, provider=None):
        XmlBase.__init__(self, Factory, "native", name)

        self.rtype = rtype
        self.standard = standard
        self.provider = provider

        self.op = []
        self.meta = {}
        self.param = {}

        self.scores = {}
        self.needs = {}
        self.coloc = {}

        if self.standard == "ocf" and not provider:
            self.provider = "heartbeat"
        elif self.standard == "lsb":
            self.provider = None

    def __setitem__(self, key, value):
        self.add_param(key, value)

    def add_op(self, name, interval, **kwargs):
        self.op.append(
            XmlBase(self.Factory, "op", "%s-%s" % (name, interval), name=name, interval=interval, **kwargs))

    def add_param(self, name, value):
        self.param[name] = value

    def add_meta(self, name, value):
        self.meta[name] = value

    def prefer(self, node, score="INFINITY", rule=None):
        if not rule:
            rule = Rule(self.Factory, "prefer-%s-r" % node, score,
                        expr=Expression(self.Factory, "prefer-%s-e" % node, "#uname", "eq", node))
        self.scores[node] = rule

    def after(self, resource, kind="Mandatory", first="start", then="start", **kwargs):
        kargs = kwargs.copy()
        kargs["kind"] = kind
        if then:
            kargs["first-action"] = "start"
            kargs["then-action"] = then

        if first:
            kargs["first-action"] = first

        self.needs[resource] = kargs

    def colocate(self, resource, score="INFINITY", role=None, withrole=None, **kwargs):
        kargs = kwargs.copy()
        kargs["score"] = score
        if role:
            kargs["rsc-role"] = role
        if withrole:
            kargs["with-rsc-role"] = withrole

        self.coloc[resource] = kargs

    def constraints(self):
        text = "<constraints>"

        for k in list(self.scores.keys()):
            text += '''<rsc_location id="prefer-%s" rsc="%s">''' % (k, self.name)
            text += self.scores[k].show()
            text += '''</rsc_location>'''

        for k in list(self.needs.keys()):
            text += '''<rsc_order id="%s-after-%s" first="%s" then="%s"''' % (self.name, k, k, self.name)
            kargs = self.needs[k]
            for kw in list(kargs.keys()):
                text += ''' %s="%s"''' % (kw, kargs[kw])
            text += '''/>'''

        for k in list(self.coloc.keys()):
            text += '''<rsc_colocation id="%s-with-%s" rsc="%s" with-rsc="%s"''' % (self.name, k, self.name, k)
            kargs = self.coloc[k]
            for kw in list(kargs.keys()):
                text += ''' %s="%s"''' % (kw, kargs[kw])
            text += '''/>'''

        text += "</constraints>"
        return text

    def show(self):
        text = '''<primitive id="%s" class="%s" type="%s"''' % (self.name, self.standard, self.rtype)
        if self.provider:
            text += ''' provider="%s"''' % (self.provider)
        text += '''>'''

        if len(self.meta) > 0:
            text += '''<meta_attributes id="%s-meta">''' % self.name
            for p in list(self.meta.keys()):
                text += '''<nvpair id="%s-%s" name="%s" value="%s"/>''' % (self.name, p, p, self.meta[p])
            text += '''</meta_attributes>'''

        if len(self.param) > 0:
            text += '''<instance_attributes id="%s-params">''' % self.name
            for p in list(self.param.keys()):
                text += '''<nvpair id="%s-%s" name="%s" value="%s"/>''' % (self.name, p, p, self.param[p])
            text += '''</instance_attributes>'''

        if len(self.op) > 0:
            text += '''<operations>'''
            for o in self.op:
                key = o.name
                o.name = "%s-%s" % (self.name, key)
                text += o.show()
                o.name = key
            text += '''</operations>'''

        text += '''</primitive>'''
        return text

    def commit(self):
        self._run("create", self.show(), "resources")
        self._run("modify", self.constraints())


class Group(Resource):
    def __init__(self, Factory, name):
        Resource.__init__(self, Factory, name, None, None)
        self.tag = "group"

    def __setitem__(self, key, value):
        self.add_meta(key, value)

    def show(self):
        text = '''<%s id="%s">''' % (self.tag, self.name)

        if len(self.meta) > 0:
            text += '''<meta_attributes id="%s-meta">''' % self.name
            for p in list(self.meta.keys()):
                text += '''<nvpair id="%s-%s" name="%s" value="%s"/>''' % (self.name, p, p, self.meta[p])
            text += '''</meta_attributes>'''

        for c in self.children:
            text += c.show()
        text += '''</%s>''' % self.tag
        return text


class Clone(Group):
    def __init__(self, Factory, name, child=None):
        Group.__init__(self, Factory, name)
        self.tag = "clone"
        if child:
            self.add_child(child)

    def add_child(self, resource):
        if not self.children:
            self.children.append(resource)
        else:
            self.Factory.log("Clones can only have a single child. Ignoring %s" % resource.name)
