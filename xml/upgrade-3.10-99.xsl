<?xml version="1.0" encoding="UTF-8"?>

<!--
 Use comments liberally as future maintainers may be unfamiliar with XSLT.
 -->

<!--
 upgrade-3.10-99.xsl

 Guarantees after this transformation:
 * All attributes of type ID are unique (assuming that was the case for the
   original input XML). Any elements with id-refs that were resolved in the
   first step of the transformation pipeline have been converted back to
   id-refs. See upgrade-3.10-common.xsl for details.
 * If an acl_permission has a reference attribute, it's a valid IDREF. This was
   the case before the transformation pipeline began, but element removals in
   earlier stages may have invalidated some ACL permissions.

 This file is numbered 99 because it must be the last stylesheet in the
 pipeline. This numbering allows us to add more stylesheets without needing to
 continually rename this one. When all transformation development work is
 finished, we can re-number it.
 -->

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:import href="upgrade-3.10-common.xsl"/>

<!-- Index all elements by ID -->
<xsl:key name="element_id" match="*" use="@id"/>

<!-- Copy everything unaltered by default -->
<xsl:template match="/|@*|node()">
    <xsl:call-template name="identity"/>
</xsl:template>

<!--
 Warn once per document if there exists an ACL permission with xpath and an
 element has been dropped, changed, or created.
 -->
<xsl:template match="/cib
                     [//acl_permission[@xpath]
                      and (//drop|//@changed|*[not(@original = 1)])]">
    <xsl:call-template name="warning">
        <!--
         Technically the ACLs are still valid but may no longer match what they
         were intended to match.
         -->
        <xsl:with-param name="msg"
                        select="concat('CIB syntax changes may invalidate ACLs',
                                       ' that use &quot;xpath&quot;.',
                                       ' It is strongly recommended to run',
                                       ' &quot;cibadmin --upgrade&quot;',
                                       ' and then examine the updated CIB',
                                       ' carefully to ensure ACLs still match',
                                       ' the desired intent.')"/>
    </xsl:call-template>

    <xsl:call-template name="identity"/>
</xsl:template>

<!--
 If an element was converted from id-ref to the referenced element earlier in
 the upgrade transformation pipeline, convert it back to an id-ref as described
 in upgrade-3.10-common.xsl
 -->
<xsl:template match="*[@id]">
    <!--
     Convert to an id-ref if @original is 0 or unset and
     * there is any element with the same id value and original="1", or
     * there is any preceding element with the same id value

     The preceding axis doesn't include ancestors. While it would likely be
     nonsense to reference an ancestor, it is allowed by the schema.

     The idea for the second point is that if all elements with a given id value
     have original set to "0" or unset, the first one should remain a definition
     while the rest become references.
     -->
    <xsl:choose>
        <xsl:when test="not(number(@original))
                        and (//*[(@id = current()/@id) and number(@original)]
                             or preceding::*[@id = current()/@id]
                             or ancestor::*[@id = current()/@id])">
            <xsl:copy>
                <xsl:attribute name="id-ref">
                    <xsl:value-of select="@id"/>
                </xsl:attribute>
            </xsl:copy>
        </xsl:when>

        <xsl:otherwise>
            <xsl:call-template name="identity"/>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<!-- Drop "dropped" elements and "changed" attributes -->
<xsl:template match="//dropped|//@changed"/>

<!-- Drop "original" attribute -->
<xsl:template match="@original"/>


<!-- ACLs -->

<!--
 "Drop" ACL permissions that refer to a nonexistent element ID.

 Rather than truly dropping the permission, we replace its reference attribute
 with an xpath attribute whose value ("/*[false()]") doesn't match anything.
 This avoids dependency chains in which one ACL permission refers to the ID of
 another ACL permission that is also removed at this stage.
 -->
<xsl:template match="acl_permission
                     [@reference and not(key('element_id', @reference))]
                     /@reference">
    <xsl:attribute name="xpath">
        <xsl:value-of select="'/*[false()]'"/>
    </xsl:attribute>
</xsl:template>

</xsl:stylesheet>
