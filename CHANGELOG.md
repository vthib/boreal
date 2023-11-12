# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2023-12-11

### Boreal

- Add rule metadata and tags in results of scans. Only the rule name and
  namespace was listed, which was an oversight.
  In addition, the `Metadata` and `MetadataValue` structs from `boreal-parser`
  are re-exported, to avoid having to depend on it to inspect matched rules
  metadatas.
  See [PR #85](https://github.com/vthib/boreal/pull/85).

## [0.3.0] - 2023-09-12

This is a huge release containing several months of work, including:

- Full compatibility with Yara 4.3. All the new features from Yara 4.3
  are available.

- A complete rewrite of the strings compilation algorithm. Performance
  has been improved dramatically when using a lot of rules or when using
  strings of lesser quality. See the [updated benchmarks](/benches/README.md).

- New tools to debug and improve performances of rules scanning, which new
  flags to display several kind of statistics.
  - Strings statistics can now be computed: how are strings compiled,
    the quality of the extracted atoms, ...j
  - Evaluation duration statistics can now be computed, detailing how long each
    evaluation step takes. This is only available if the new `profiling` feature
    is enabled, to not impact evaluation performance if not set.

- Improved testing on modules and on the `boreal-cli` binary.

Here are some more details on the new YARA features:

Yara 4.3:

- Negation in hex strings, eg `{ ~C3 ~?F }`.
- New `to_string` function in `math` module.
- New `string` module with `to_int` and `length` functions.
- `rva` field in imported functions in `pe` module.
- `pe.import_rva` and `pe.delayed_import_rva` functions.
- `pe.rich_signature.version_data` field.
- Iterator on bytes literal, eg `for any s in ("foo", "bar"): (...)`.
- `at` for expression, eg `any of them at 0`.
- New functions `import_md5` and `telfhash` in `elf` module.
- Use of the `authenticode-parser` lib to parse signatures in `pe` module.
  This adds a lot of fields in `pe.signatures`.

Here are the changes grouped by crate:

### Boreal

#### Added

- Yara 4.3 compatibility. Too many features to list, see above
  for a short recap of the main new features.
- New `profiling` feature, needed to compute evaluation statistics.

#### Changed

- Rewrite of the strings compilation algorithm to significantly improve
  statistics.
- `openssl` feature removed, replaced with the `authenticode` feature.
- Using the `pe` module with the `signatures` parsing now requires
  calling the unsafe function `Compiler::new_with_pe_signatures`.
- All dependencies updated. `regex` has been removed in favor
  of `regex-automata`.

#### Fixed

- Improved handling on invalid ranges in '$a in (from..to)' expression.
- Fixed minor differences in edge cases in `elf.dynamic_section_entries` and
  ``elf.number_of_sections` ([e639df643b05](https://github.com/vthib/boreal/commit/e639df643b05)).
- Fixed `==` operator on boolean values ([cec439eee19f](https://github.com/vthib/boreal/commit/cec439eee19f)).
- Fixed some bugs occuring when using the `fullword` keyword with
  both the `wide` and `ascii` modifiers, see [PR #51](https://github.com/vthib/boreal/pull/51).
- Fix compilation of rules following the failed compilation of a rule using
  a rule dependency. I doubt this actually impacted anyone, see [PR #60](https://github.com/vthib/boreal/pull/60).
- Change regex behavior to allow non ascii bytes in regexes. See [PR #62](https://github.com/vthib/boreal/pull/62).
  A warning has however been added to warn against this situation.
- Fixed string comparison in the `pe.imports` and `pe.(delayed_)import_rva`
  functions to be case-insensitive, See [PR #69](https://github.com/vthib/boreal/pull/69).

### boreal-cli

#### Added

- New `-M` flag to a list of available modules.
- New `--string-stats` flag to display strings' compilation statistics.
- New `--scan-stats` flag to display evaluation duration statistics.

#### Changed

- Number of dependencies reduced by removing any use of proc macros.
- `boreal` updated to 0.3, see `boreal` changes.

### boreal-parser

#### Added

- Parsing of negation in hex strings, eg `{ ~C3 ~?F }` ([9c21fd446](https://github.com/vthib/boreal/commit/9c21fd446)).
- Parsing of `at` for expression, eg `any of them at 0` ([b26fbc3b6](https://github.com/vthib/boreal/commit/b26fbc3b6)).
- `parse_regex` and `parse_hex_string` added to public API ([d6a7afc98](https://github.com/vthib/boreal/commit/d6a7afc98)).

#### Changed

- Exports of the crate have been entirely reworked. Objects are
  now nested in relevant modules ([3e8682bec](https://github.com/vthib/boreal/commit/3e8682bec)).
- Removal of `bitflags` dependency, rework of `VariableModifiers`
  object ([05877aae4](https://github.com/vthib/boreal/commit/05877aae4)).
- Regex now accepts non ascii bytes when not in a class. See [PR #62](https://github.com/vthib/boreal/pull/62).
- AST for bytes and characters in a regex has been updated to
  provide escaping information and span location. See [PR #68](https://github.com/vthib/boreal/pull/68).

#### Fixed

- Some public objects were not properly exposed publicly, this
  should now be fixed ([3e8682bec](https://github.com/vthib/boreal/commit/3e8682bec)).

## [0.2.0] - 2023-02-12

Main changes:

- Compilation and evaluation of rules have been hardened, and it is now
  possible to use `boreal` with untrusted rules and inputs.
  - Protections against stack overflows in parsing and evaluation
  - Optional timeout usable during scans.
  - Limits for all arrays in module values (`elf`, `pe`, `macho`).
- Several corner cases in parsing of PE files have been handled, fixing
  a few inconsistencies with YARA.
- A new warning system has been added, compiled rules can now generate
  warnings.

### Added

- Stack overflow protection during parsing and evaluation.
- Add warning when implicitly converting bytes to boolean (same as in YARA).
- Add `AddRuleStatus` object returned after compiling rules. This contains
  warnings emitted during compilation.
- Added new `CompilerParams` with tweakable params during compilation.
  - `max_condition_depth` to modify the stack overflow protection limit.
  - `fail_on_warnings` to ensure all warnings behave as errors.
- Add timeout parameter in `ScanParams`: any scanning is aborted once the
  timeout is reached.
- Minimal Rust version is now 1.62 and checked in CI
- `ModuleValue` now has an `Undefined` value.
- `openssl` feature for `boreal-cli`.
- **CI**: Coverage computation
- **CI**: Build with openssl is now properly tested on Windows.

### Changed

- Module values are now tested for exact match with module values produced
  by YARA. This caught a few bugs and improves compatibility.

### Fixed

- Ordinal functions in PE module now always have a name, defaulting to `ord{n}`.
  (41554fc2bc).
- `pe.IMPORT_STANDARD` and `pe.IMPORT_DELAYED` now have the proper values
  (0fa2477d06).
- `pe.number_of_version_infos` is now always set (86c6366684).
- `pe.export_details[*].offset` is now set to -1 when the offset is invalid
  (122d8bc6a9).
- `pe.version_info` is now properly built when values are padded in the file
  (fe7c2356d).
- `pe.imports` is now properly built when OriginalFirstThunk is invalid
  (3369ab3ad).
- The `pe` module now properly parses sections with VirtualSize = 0
  (5a3202718).
- Generate an error when an identifier bounded by a for expression is used
  in the iterator (#15).
- `pe.entry_point` is now -1 when its file offset is outside the file
  (#16).

### Removed

- `boreal::module::StaticValue::Regex` has been removed (a7e543b1dee).
- Removed errors `VariableCompilationError::AtomsExtractionError` and
  `VariableCompilationError::WidenError`. Those were logic errors that shouldn't
  be exposed to users.

## [0.1.0] - 2022-12-04

Initial release.

[unreleased]: https://github.com/vthib/boreal/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/vthib/boreal/releases/tag/v0.2.0
[0.1.0]: https://github.com/vthib/boreal/releases/tag/v0.1.0
