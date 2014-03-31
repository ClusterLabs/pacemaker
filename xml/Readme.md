# Updating schema files #

## Experimental features ##

Experimental features go into `${base}-next.rng`

Create from the most recent `${base}-${X}.${Y}.rng` if it does not already exist

## Stable features ##

The current stable version is set by  `CRM_DTD_VERSION` in `configure.ac` and has the form `${X}.${Y}`.
Bump `${X}` and set `${Y}` to `0` for syntax removals, bump `${Y}` for additions and then,

1. Update the value `configure.ac`,
1. Add the new `${X}.${Y}` to `RNG_versions` in xml/Makefile.am,
1. Add the new `${X}.${Y}` to `xml/versions.rng`
1. Copy the most recent version of `${base}-*.rng` to `${base}-${X}.${Y}.rng`
1. TBA: Possibly we should be bumping CRM_FEATURE_SET too
1. Update `known_schemas` in `lib/common/xml.c`, add it prior to the entry for `pacemaker-next`.
   The second last field of the previous entry needs to be set to `0`.
   For example:
            
        /* 6 */    { 2, "pacemaker-1.2",  NULL, NULL, -1, NULL },
        /* - */    { 2, "pacemaker-next", NULL, NULL, -1, NULL }, /* Feature playground */
            
   becomes:
            
        /* 6 */    { 2, "pacemaker-1.2",  NULL, NULL,  0, NULL },
        /* 7 */    { 2, "pacemaker-1.3",  NULL, NULL, -1, NULL },
        /* - */    { 2, "pacemaker-next", NULL, NULL, -1, NULL }, /* Feature playground */


## Incompatible changes

When the new syntax is not a simple addition to the previous one, an XSLT file is required that converts an old syntax to the new one.
See `xml/upgrade06.xsl` for an example.