<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text"/>
<xsl:param name="goal-name" select="'id'"/>
<xsl:param name="goal-value" select="'GOAL'"/>
<xsl:param name="style" select="'rng'"/>
<xsl:param name="skip" select="0"/>

<xsl:template match="/">
    <xsl:choose>
        <xsl:when test="not(.//@*[
                            name() = $goal-name
                            and
                            . = $goal-value
                        ])">
            <xsl:message terminate="yes">NOTFOUND</xsl:message>
        </xsl:when>
        <xsl:when test="$style = 'xml'">
            <xsl:call-template name="xpath-xml-elem">
                <xsl:with-param name="terminal-elem"
                                select=".//@*[
                                            name() = $goal-name
                                            and
                                            . = $goal-value
                                        ]/.."/>
            </xsl:call-template>
        </xsl:when>
        <xsl:when test="$style = 'rng'">
            <xsl:call-template name="xpath-rng-elem">
                <xsl:with-param name="terminal-elem"
                                select=".//@*[
                                            name() = $goal-name
                                            and
                                            . = $goal-value
                                        ]/.."/>
            </xsl:call-template>
        </xsl:when>
        <xsl:otherwise>
            <xsl:message terminate="yes">BADSTYLE</xsl:message>
        </xsl:otherwise>
    </xsl:choose>
</xsl:template>

<xsl:template name="xpath-xml-elem">
    <xsl:param name="terminal-elem"/>
    <xsl:variable name="TotalCount"
                  select="count($terminal-elem/ancestor-or-self::*)"/>
    <xsl:for-each select="$terminal-elem/ancestor-or-self::*">
        <xsl:if test="$TotalCount - position() &gt;= $skip">
            <xsl:value-of select="concat('/', name())"/>
        </xsl:if>
    </xsl:for-each>
    <xsl:value-of select="'&#xa;'"/>
</xsl:template>

<xsl:template name="xpath-rng-elem">
    <xsl:param name="terminal-elem"/>
    <xsl:variable name="TotalCount"
                  select="count($terminal-elem/ancestor-or-self::*)"/>
    <xsl:for-each select="$terminal-elem/ancestor-or-self::*">
        <xsl:if test="$TotalCount - position() &gt;= $skip">
            <xsl:choose>
                <xsl:when test="name() = 'attribute'">
                    <xsl:value-of select="concat('/@', @name)"/>
                </xsl:when>
                <xsl:when test="name() = 'define'">
                    <xsl:value-of select="concat('/&lt;', @name, '&gt;')"/>
                </xsl:when>
                <xsl:when test="name() = 'element'">
                    <xsl:value-of select="concat('/', @name)"/>
                </xsl:when>
                <xsl:when test="name() = 'grammar'">
                    <xsl:if test="$TotalCount &lt; 3">
                        <xsl:value-of select="concat('&lt;', name(), '&gt;')"/>
                    </xsl:if>
                </xsl:when>
            </xsl:choose>
        </xsl:if>
    </xsl:for-each>
    <xsl:value-of select="'&#xa;'"/>
</xsl:template>

</xsl:stylesheet>
