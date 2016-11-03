# Schema Reference

Besides the version of Pacemaker itself, the XML schema of the Pacemaker
configuration has its own version.

## Versioned Schema Evolution

A versioned schema offers transparent backward/forward compatibility.

- It reflects the timeline of schema-backed features (introduction,
  changes to the syntax, possibly deprecation) through the versioned
  stable schema increments, while keeping schema versions used by default
  by older Pacemaker versions untouched.

- Pacemaker internally uses the latest stable schema version, and relies on
  supplemental transformations to promote cluster configurations based on
  older, incompatible schema versions into the desired form.

- It allows experimental features with a possibly unstable configuration
  interface to be developed using the special `next` version of the schema.

## Mapping Pacemaker Versions to Schema Versions

| Pacemaker | Latest Schema | Changed
| --------- | ------------- | ----------------------------------------------
| `1.1.15`  | `2.5`         | `alerts`
| `1.1.14`  | `2.4`         | `fencing`
| `1.1.13`  | `2.3`         | `constraints`
| `1.1.12`  | `2.0`         | `nodes`, `nvset`, `resources`, `tags` + `acls`
| `1.1.8`+  | `1.2`         |

# Updating schema files #

## Experimental features ##

Experimental features go into `${base}-next.rng`

Create from the most recent `${base}-${X}.${Y}.rng` if it does not already exist

## Stable features ##

The current stable version is determined at runtime when
__xml_build_schema_list() interrogates the CRM_DTD_DIRECTORY.

It will have the form `pacemaker-${X}.${Y}` and the highest
`${X}.${Y}` wins.

### Simple Additions

When the new syntax is a simple addition to the previous one, create a
new entry with `${Y} = ${Yold} + 1`

### Feature Removal or otherwise Incompatible Changes

When the new syntax is not a simple addition to the previous one,
create a new entry with `${X} = ${Xold} + 1` and `${Y} = 0`.

An XSLT file is also required that converts an old syntax to the new
one and must be named `upgrade-${Xold}.${Yold}.xsl`.

See `xml/upgrade06.xsl` for an example.

### General Proceedure

1. Copy the most recent version of `${base}-*.rng` to `${base}-${X}.${Y}.rng` 
1. Commit the copy, eg. `"Clone the latest ${base} schema in preparation for changes"`.  
   This way the actual change will be obvious in the commit history.
1. Modify `${base}-${X}.${Y}.rng` as required
1. Add an XSLT file if required and update `xslt_SCRIPTS` in `xml/Makefile.am` 
1. Commit

## Admin Tasks
New features will not be available until the admin

1. Updates all the nodes
1. Runs the equivalent of `cibadmin --upgrade`

## Random Notes

From the source directory, run `make -C xml diff` to see the changes
in the current schema (compared to the previous ones) and also the
pending changes in `pacemaker-next`.
Alternatively, if the intention is to grok the overall historical schema
evolution, use `make -C xml fulldiff`.
