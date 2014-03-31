
# Updating schema files #

## Experimental features ##

Experimental features go into `${base}-next.rng`

Create from the most recent `${base}-${X}.${Y}.rng` if it does not already exist

## Stable features ##

For stable features, copy the most recent version to `${base}-${X}.${Y}.rng`

Bump `${X}` for removals, bump `${Y}` for additions and update `CRM_DTD_VERSION` in `configure.ac`


