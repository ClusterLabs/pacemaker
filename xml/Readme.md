# Schema Reference

Pacemaker's XML schema has a version of its own, independent of the version of
Pacemaker itself.

## Versioned Schema Evolution

A versioned schema offers transparent backward and forward compatibility.

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
| `1.1.18`  | `2.10`        | `resources`, `alerts`
| `1.1.17`  | `2.9`         | `resources`, `rule`
| `1.1.16`  | `2.6`         | `constraints`
| `1.1.15`  | `2.5`         | `alerts`
| `1.1.14`  | `2.4`         | `fencing`
| `1.1.13`  | `2.3`         | `constraints`
| `1.1.12`  | `2.0`         | `nodes`, `nvset`, `resources`, `tags` + `acls`
| `1.1.8`+  | `1.2`         |

## Schema generation

Each logical portion of the schema goes into its own RNG file, named like
`${base}-${X}.${Y}.rng`. `${base}` identifies the portion of the schema
(e.g. constraints, resources); ${X}.${Y} is the latest schema version that
contained changes in this portion of the schema.

The complete, overall schema, `pacemaker-${X}.${Y}.rng`, is automatically
generated from the other files via the Makefile.

# Updating schema files #

## Experimental features ##

Experimental features go into `${base}-next.rng` where `${base}` is the
affected portion of the schema. If such a file does not already exist,
create it by copying the most recent `${base}-${X}.${Y}.rng`.

Pacemaker will not use the experimental schema by default; the cluster
administrator must explicitly set the `validate-with` property appropriately to
use it.

## Stable features ##

The current stable version is determined at runtime when
crm_schema_init() scans the CRM_DTD_DIRECTORY.

It will have the form `pacemaker-${X}.${Y}` and the highest
`${X}.${Y}` wins.

### Simple Additions

When the new syntax is a simple addition to the previous one, create a
new entry, incrementing `${Y}`.

### Feature Removal or otherwise Incompatible Changes

When the new syntax is not a simple addition to the previous one,
create a new entry, incrementing `${X}` and setting `${Y} = 0`.

An XSLT file is also required that converts an old syntax to the new
one and must be named `upgrade-${Xold}.${Yold}.xsl`.

See `xml/upgrade-1.3.xsl` for an example.

### General Procedure

1. Copy the most recent version of `${base}-*.rng` to `${base}-${X}.${Y}.rng` 
1. Commit the copy, e.g. `"Low: xml: clone ${base} schema in preparation for
   changes"`. This way, the actual change will be obvious in the commit history.
1. Modify `${base}-${X}.${Y}.rng` as required.
1. If required, add an XSLT file, and update `xslt_SCRIPTS` in `xml/Makefile.am`.
1. Commit
1. `make -C xml clean; make -C xml all` to rebuild the schemas in the local
   source directory.
1. The CIB validity regression tests will break after the schema is updated.
   Run `tools/regression.sh` to get the new output,
   `diff tools/regression.validity.{out,exp}` to ensure the changes look correct,
   `cp tools/regression.validity.{out,exp}` to update the expected output,
   then commit the change.

## Using a New Schema

New features will not be available until the cluster administrator:

1. Updates all the nodes
1. Runs the equivalent of `cibadmin --upgrade --force`

## Random Notes

From the source directory, run `make -C xml diff` to see the changes
in the current schema (compared to the previous ones) and also the
pending changes in `pacemaker-next`.
Alternatively, if the intention is to grok the overall historical schema
evolution, use `make -C xml fulldiff`.
