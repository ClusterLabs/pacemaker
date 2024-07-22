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
 If needed, create a new nvset to handle dropping a default-valued nvpair.

 The context node is assumed to be an nvpair whose value might be unset by a
 default-valued nvpair with the same name in another nvset.

 If the current nvpair will certainly be unset, we drop it. Otherwise, we create
 a new nvset to contain the current nvpair. The new nvset has a rule so that it
 will be applied only if none of $default_nvsets would have been applied in the
 input XML.

 Params:
 * default_nvsets:  nvsets containing a default-valued nvpair that would unset
                    the current nvpair if applied
 * id_suffix:       Suffix for newly created nvset's id
 -->
<xsl:template name="handle_defaults_new_nvset">
    <xsl:param name="default_nvsets"/>
    <xsl:param name="id_suffix"/>

    <xsl:variable name="current_nvpair" select="."/>
    <xsl:variable name="current_nvset" select=".."/>

    <!--
     If an nvset in $default_nvsets doesn't contain a rule, then it will be
     applied unconditionally, and the current nvpair will certainly not take
     effect. In that case, we can skip creating a new nvset and simply drop the
     current nvpair.
     -->
    <xsl:if test="not($default_nvsets[not(rule)])">
        <xsl:variable name="new_nvset_id"
                      select="concat($upgrade_prefix, @id, $id_suffix)"/>

        <!--
         for-each is used here just to change the context node, so that we can
         use copy to create a new element of the same type as the current nvset
         -->
        <xsl:for-each select="$current_nvset">
            <!-- Create the new nvset -->
            <xsl:copy>
                <!--
                 Copy current nvset's attributes, overriding id and original
                 -->
                <xsl:apply-templates select="@*"/>
                <xsl:attribute name="original">0</xsl:attribute>
                <xsl:attribute name="id">
                    <xsl:value-of select="$new_nvset_id"/>
                </xsl:attribute>

                <!--
                 New rule: if the current nvset's rule evaluates to true, and
                 all the rules in $default_nvsets evaluate to false, apply the
                 new nvset (which will contain the current nvpair)
                 -->
                <xsl:element name="rule">
                    <xsl:attribute name="id">
                        <xsl:value-of select="concat($new_nvset_id, '-rule')"/>
                    </xsl:attribute>

                    <!-- Reference to rule of current nvset, if any -->
                    <xsl:apply-templates select="$current_nvset/rule">
                        <xsl:with-param name="original" select="'0'"/>
                    </xsl:apply-templates>

                    <!-- Negations of all rules in $default_nvsets -->
                    <xsl:for-each select="$default_nvsets/rule">

                        <!-- Wrapper that negates the rule -->
                        <xsl:element name="rule">
                            <xsl:attribute name="id">
                                <xsl:value-of select="concat($upgrade_prefix,
                                                             @id, '-negated')"/>
                            </xsl:attribute>
                            <xsl:attribute name="negate">1</xsl:attribute>

                            <!--
                             Copy of original rule (will be converted back to an
                             idref later)
                             -->
                            <xsl:apply-templates select=".">
                                <xsl:with-param name="original" select="'0'"/>
                            </xsl:apply-templates>
                        </xsl:element>
                    </xsl:for-each>
                </xsl:element>

                <!-- Add the current nvpair to the new nvset -->
                <xsl:apply-templates select="$current_nvpair"/>
            </xsl:copy>
        </xsl:for-each>
    </xsl:if>
</xsl:template>

<!--
 Update an nvset (the context node) to handle special default-valued nvpairs.
 * Drop nvpairs with default values.
 * As needed, create new nvsets with rules to account for dropping default-
   valued nvpairs in other nvsets.

 Applying a default-valued nvpair in one nvset may unset or take precedence over
 over an nvpair with the same name in a different nvset. Thus dropping a
 default-valued nvpair from one nvset may affect whether an nvpair in a
 different nvset gets applied.

 This template creates new nvsets with rules that preserve behavior for this
 nvset's nvpairs, even if default-valued nvpairs are dropped from other nvsets.

 Here, we use "unset" to mean that a default-valued nvpair in another nvset
 either unsets or takes precedence over an nvpair with the same name in the
 current nvset.

 Params:
 * candidate_default_nvsets: Sibling nvsets of the same element type as the
                             current nvset, that may contain nvpairs with
                             default values that could unset nvpairs in the
                             current nvset
 * default_value:            Value that, if applied in one of
                             candidate_default_nvsets for some nvpair, would
                             unset a same-named nvpair in the current nvset
 -->
<xsl:template name="handle_defaults">
    <xsl:param name="candidate_default_nvsets"/>
    <xsl:param name="default_value"/>

    <!--
     nvpairs that may be unset by a default value in one of
     $candidate_default_nvsets
     -->
    <xsl:variable name="candidate_unset_nvpairs"
                  select="nvpair
                          [(@value != $default_value)
                           and (@name
                                = $candidate_default_nvsets
                                  /nvpair[@value = $default_value]/@name)]"/>

    <!--
     nvpairs to keep in the current nvset:
     * If an nvpair has value $default_value, then it's dropped.
     * If an nvpair may be unset, then it's handled in the for-each, where it's
       either placed in a newly created nvset or dropped.
     -->
    <xsl:variable name="kept_nvpairs"
                  select="nvpair[(@value != $default_value)
                                 and (count(.|$candidate_unset_nvpairs)
                                      != count($candidate_unset_nvpairs))]"/>

    <xsl:for-each select="$candidate_unset_nvpairs">
        <!--
         Create a new nvset that applies the current nvpair only if it would not
         be unset by a default value in another nvset
         -->
        <xsl:call-template name="handle_defaults_new_nvset">
            <xsl:with-param name="default_nvsets"
                            select="$candidate_default_nvsets
                                    [nvpair[(@value = $default_value)
                                            and (@name = current()/@name)]]"/>

            <xsl:with-param name="id_suffix">
                <xsl:choose>
                    <xsl:when test="$default_value = '#default'">
                        <xsl:value-of select="'-no-hash-default'"/>
                    </xsl:when>
                </xsl:choose>
            </xsl:with-param>
        </xsl:call-template>
    </xsl:for-each>

    <!--
     Copy the current nvset without the nvpairs that may be unset (handled by
     for-each above) and without default values
     -->
    <xsl:copy>
        <xsl:apply-templates select="@*
                                     |node()[not(self::nvpair)]
                                     |$kept_nvpairs"/>
    </xsl:copy>
</xsl:template>

</xsl:stylesheet>
