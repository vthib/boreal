# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Main changes:

- Lots of improved testing on modules and on the `boreal` binary, as well as running
  all tests in a big-endian architecture.

### Fixed

- Fixed minor differences in edge cases in `elf.dynamic_section_entries` and
  ``elf.number_of_sections` (e639df643b05).
- Fixed `==` operator on boolean values (cec439eee19f).

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
