# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

The `boreal` CLI tool has been improved and reworked greatly. It now uses subcommands to
distinguish the different invocation modes:

- The `yr` subcommand guarantees the same interface as the `yara` CLI tool. All the yara
  options are supported (except for `--atom-quality-table`).
- The `scan` subcommand is the main subcommand, with globally the same interface but
  with less ambiguous invocation with multiple rule files, which are specified using
  the `-f` flag:

  `boreal -f rule1.yar -f rule2.yar file_to_scan`

- The `save` subcommand can be used to serialize the compiled rules into a file, an
  equivalent to `yarac`.
- The `load` subcommand can be used to load serialized compiled rules and use it to
  scan inputs.
- The `list-modules` is the equivalent to the `-M` flag which lists the available modules.

### Breaking changes:

- Reworked boreal-cli to use subcommands [#222](https://github.com/vthib/boreal/pull/222).

### Added

- Allow passing multiple rules file and specifying namespace [#223](https://github.com/vthib/boreal/pull/223).
- Added `save` subcommand and `load` subcommand (`-C/--compiled-rules` in `yr` subcommand to
  respectively save compiled rules into a file and load compiled rules from a file.
  This mirrors the yarac binary and the -C option in yara
  [54b01f2](https://github.com/vthib/boreal/commit/54b01f2c10f57be95e20230e5566a0141e45e86d).
- Added -n/--negate option to print non matching rules, mirroring the equivalent in the yara
  CLI tool
  [9fc0d73](https://github.com/vthib/boreal/commit/9fc0d73b48b6ba535eaa235e66525b576176c669).
- Added -c/--count option to print the number of matching rules (or non matching if negated),
  mirroring the equivalent in the yara CLI tool
  [28722ec](https://github.com/vthib/boreal/commit/28722ec0fab8a97b9649b0aff8454fd3b18b7d05).
- Added -l/--max-rules option to abort the scan once a certain number of rules has matched
 (or not matched if negated), mirroring the equivalent in the yara CLI tool
  [5fc7ac5](https://github.com/vthib/boreal/commit/5fc7ac5f7cff2bad712f07619ccaa5002b723f23).
- Added --max-strings-per-rule to fail compilation if a rule contains too many strings,
  mirroring the equivalent in the yara CLI tool
  [b48f8cf](https://github.com/vthib/boreal/commit/b48f8cf94673a9d5ae1e29a39c24028105b4e3e2)
- Added -X/--print-xor-key to display xor key used on string match, mirroring the equivalent
  in the yara CLI tool
  [35bf7c4](https://github.com/vthib/boreal/commit/35bf7c48866d6bccdf64b37407fc4e5410997a68).
- Added --string-max-nb-matches to display a warning when a string has too many matches
  [bda80aa](https://github.com/vthib/boreal/commit/bda80aad322133cec0177151f64221793272952d).
- Added -x/--module-data option to specify options for modules. This only works on
  the cuckoo module
  [5997546](https://github.com/vthib/boreal/commit/599754615110c20f4f7edaf004aed75c365a7d19).
- Accept but ignore some arguments for yara compatibility [#224](https://github.com/vthib/boreal/pull/224).

### Updated

- Use callback API to print matching rules as it happens instead of once the scan is done
  [d6eae09](https://github.com/vthib/boreal/commit/d6eae09dd534963d1e67103d16d46832cb7ff874).

### Fixed

- The module data dump flag (-D) now dumps the "static" values of a module, i.e. the values
  that do not depend on the scan [#225](https://github.com/vthib/boreal/pull/225).

## Before [1.0.0]

See [the global CHANGELOG file](../CHANGELOG.md) for older versions.

[unreleased]: https://github.com/vthib/boreal/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/vthib/boreal/compare/v0.8.0...v0.9.0
