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

## Mapping Pacemaker Versions to Schema Versions

| Pacemaker | Latest Schema | Changed
| --------- | ------------- | ----------------------------------------------
| `2.1.5`   | `3.9`         | `alerts`, `constraints`, `nodes`, `nvset`,
|           |               | `options`, `resources`, `rule`
| `2.1.3`   | `3.8`         | `acls`
| `2.1.0`   | `3.7`         | `constraints`, `resources`
| `2.0.5`   | `3.5`         | `api`, `resources`, `rule`
| `2.0.4`   | `3.3`         | `tags`
| `2.0.1`   | `3.2`         | `resources`
| `2.0.0`   | `3.1`         | `constraints`, `resources`
| `1.1.18`  | `2.10`        | `resources`, `alerts`
| `1.1.17`  | `2.9`         | `resources`, `rule`
| `1.1.16`  | `2.6`         | `constraints`
| `1.1.15`  | `2.5`         | `alerts`
| `1.1.14`  | `2.4`         | `fencing`
| `1.1.13`  | `2.3`         | `constraints`
| `1.1.12`  | `2.0`         | `nodes`, `nvset`, `resources`, `tags`, `acls`
| `1.1.8`   | `1.2`         |

## Schema generation

Each logical portion of the schema goes into its own RNG file, named like
`${base}-${X}.${Y}.rng`. `${base}` identifies the portion of the schema
(e.g. constraints, resources); ${X}.${Y} is the latest schema version that
contained changes in this portion of the schema.

The complete, overall schema, `pacemaker-${X}.${Y}.rng`, is automatically
generated from the other files via the Makefile.

# Updating schema files #

## New features ##

The current schema version is determined at runtime when
crm\_schema\_init() scans the CRM\_SCHEMA\_DIRECTORY.

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

Since `xml/upgrade-2.10.xsl`, rather self-descriptive approach is taken,
separating metadata of the replacements and other modifications to
perform from the actual executive parts, which is leveraged, e.g., with
the on-the-fly overview as obtained with `./regression.sh -X test2to3`.
Also this was the first time particular key names of `nvpair`s,
i.e. below the granularity of the schemas so far, received attention,
and consequently, no longer expected names became systemically banned
in the after-upgrade schemas, using `<except>` construct in the
data type specification pertaining the affected XML path.

The implied complexity also resulted in establishing a new compound,
stepwise transformation, alleviating the procedural burden from the
core upgrade recipe.  In particular, `id-ref` based syntactic
simplification granted in the CIB format introduces nonnegligible
internal "noise" because of the extra indirection encumbered with
generally non-bijective character of such a scheme (context-dependent
interpretation).  To reduce this strain, a symmetric arrangement is
introduced as a pair of _enter_/_leave_ (pre-upgrade/post-upgrade)
transformations where the latter is meant to eventually reversibly
restore what the former intentionally simplified (normalized) for
upgrade transformation's peruse.  It's optional (even the post-upgrade
counterpart is optional alone) and depends on whether the suitable
files are found along the upgrade transformation itself: e.g., for
`upgrade-2.10.xsl`, such files are `upgrade-2.10-enter.xsl` and
`upgrade-2.10-leave.xsl`.  Note that unfolding + refolding `id-ref`
shortcuts is just a practically imposed individual case of how to
reversibly make the configuration space tractable in the upgrade
itself, allowing for more sophistication down the road.

### General Procedure

1. Copy the most recent version of `${base}-*.rng` to `${base}-${X}.${Y}.rng`,
   such that the new file name increments the highest number of any schema file,
   not just the file being edited.
2. Commit the copy, e.g. `"Low: xml: clone ${base} schema in preparation for
   changes"`. This way, the actual change will be obvious in the commit history.
3. Modify `${base}-${X}.${Y}.rng` as required.
4. If required, add an XSLT file, and update `xslt\_SCRIPTS` in `xml/Makefile.am`.
5. Commit.
6. Run `make -C xml clean; make -C xml` to rebuild the schemas in the local
6. Run `make -C xml clean; make -C xml` to rebuild the schemas in the local
   source directory.
7. The CIB validity and upgrade regression tests will break after the schema is
   updated. Run `cts/cts-cli -s` to make the expected outputs reflect the
   changes made so far, and run `git diff` to ensure that these changes look
   sane. Finally, commit the changes.
8. Similarly, with the new major version `${X}`, it's advisable to refresh
   scheduler tests at some point. See the instructions in `cts/README.md`.

## Using a New Schema

New features will not be available until the cluster administrator:

1. Updates all the nodes
2. Runs the equivalent of `cibadmin --upgrade --force`

## Random Notes

From the source directory, run `make -C xml diff` to see the changes
in the current schema (compared to the previous ones).
Alternatively, if the intention is to grok the overall historical schema
evolution, use `make -C xml fulldiff`.
