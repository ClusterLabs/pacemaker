<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-common.xsl

 This stylesheet is intended to be imported by all other stylesheets in the
 upgrade-3.10-* pipeline. It provides variables and templates that are used by
 multiple stylesheets.

 This file should not contain any templates with a match attribute.

 Assumptions:
 * The input XML validates against the pacemaker-3.10.rng schema.
 * No element of the input XML contains an id attribute whose value begins with
   "pcmk__3_10_upgrade-". This allows us to generate new IDs without fear of
   conflict. However, the schema does not enforce this assumption.
 * For attributes of type IDREF, the referenced element is of the correct type.
   For example, the rsc attribute in a constraint refers to a resource element
   (primitive, group, clone, bundle). The schema cannot enforce this assumption;
   it requires only that each IDREF refer to a valid ID. As a result, the result
   of our transformation pipeline may fail to validate if IDREFs refer to
   unexpected element types.

 Notes:
 * A "dropped" element should always be inserted as a replacement when dropping
   an element. A "changed" attribute should always be set to 1 when changing any
   of an element's attributes. These are used at the end of the transformation
   pipeline to output a conditional warning, and they are then stripped.

 @TODO Try to clean up IDREFs to unexpected element types when the referenced
 elements are removed.
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<!-- Strip whitespace-only text nodes but indent output -->
<xsl:strip-space elements="*"/>
<xsl:output encoding="UTF-8" indent="yes" omit-xml-declaration="yes"/>

<!-- Prefix for auto-generated IDs -->
<xsl:variable name="upgrade_prefix" select="'pcmk__3_10_upgrade-'"/>

<!--
 Modified identity transformation. Copy everything unaltered by default, but set
 the "original" attribute based on the "original" template param.

 "original" is a temporary attribute to indicate that an element existed in the
 input XML. It's not allowed by the schema for any element, so we don't have to
 worry about conflicts.

 The first step in the upgrade pipeline is to resolve id-ref attributes (type
 IDREF) to id attributes (type ID). We do this as follows. For each element with
 an id-ref attribute, replace that element with a deep copy of the referenced
 element. Set the "original" attribute to 0 in the copy.

 At the end of the upgrade pipeline, we convert back to references as follows.
 For each element with an id attribute and with the "original" attribute either
 unset or set to 0:
 * If there is another element with the same id value that either occurs before
   the current element or has original="1", convert the current element back to
   a reference with only the id-ref attribute.
 * Otherwise, drop the "original" attribute and leave the rest of the current
   element's attributes and descendants unchanged (except for converting
   descendants back to references if needed).

 Notes:
 * We resolve all attributes named id-ref (which are of type IDREF). We do not
   resolve all attributes of type IDREF. We resolve only in the places where
   either a definition (with id) or a reference (with id-ref) would validate
   against the pacemaker-3.10 schema (ignoring ID uniqueness requirements after
   resolution).
 * If the "original" attribute is unset for an element, the end of the
   transformation pipeline treats the element as if it had original="0".
 * By default, if the "original" param is set, then it's passed down with the
   same value for all descendants.
 -->

<!--
 Identity transformation, optionally setting the "original" attribute

 Params:
 * original: Boolean (1/0) indicating whether an element was part of the
             original input XML. If set and this is an element node, the param
             is used as the value for the "original" attribute for this element
             and its descendants.
 -->
<xsl:template name="identity">
    <xsl:param name="original"/>

    <xsl:copy>
        <!-- All existing attributes -->
        <xsl:apply-templates select="@*"/>

        <xsl:if test="self::* and $original">
            <!-- Set "original" attribute for element nodes -->
            <xsl:attribute name="original">
                <xsl:value-of select="$original"/>
            </xsl:attribute>
        </xsl:if>

        <!-- All nodes, passing down $original value recursively -->
        <xsl:apply-templates select="node()">
            <xsl:with-param name="original" select="$original"/>
        </xsl:apply-templates>
    </xsl:copy>
</xsl:template>

<!--
 Outputs a warning message

 Output a message with the prefix "WARNING: ". This directs Pacemaker's XSLT
 error handler to strip the prefix and log the message at warning level.

 Params:
 * msg: Message to output
 -->
<xsl:template name="warning">
    <xsl:param name="msg"/>

    <xsl:message>
        <xsl:value-of select="concat('WARNING: ', $msg)"/>
    </xsl:message>
</xsl:template>

<!--
 Outputs an info message

 Output a message with the prefix "INFO: ". This directs Pacemaker's XSLT error
 handler to strip the prefix and log the message at info level.

 Params:
 * msg: Message to output
 -->
<xsl:template name="info">
    <xsl:param name="msg"/>

    <xsl:message>
        <xsl:value-of select="concat('INFO: ', $msg)"/>
    </xsl:message>
</xsl:template>

</xsl:stylesheet>
