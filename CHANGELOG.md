# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2024-04-14

This release mainly adds the `dotnet` module and simplifies a few dependencies.

### boreal

#### Added:

* The `dotnet` module is now available behind the `object` feature (enabled by default).
  [#127](https://github.com/vthib/boreal/pull/127), [#131](https://github.com/vthib/boreal/pull/131),
  [#133](https://github.com/vthib/boreal/pull/133), [#135](https://github.com/vthib/boreal/pull/135).

#### Fixed:

- Fixed compilation when using `--no-default-features` and other feature combinations.
  [#129](https://github.com/vthib/boreal/pull/129), [#130](https://github.com/vthib/boreal/pull/130).
- Fixed exposure of some optional dependencies as their own features.
  [#128](https://github.com/vthib/boreal/pull/128).
- Added CI jobs to ensure common combinations of features compile and run tests properly.
  [#132](https://github.com/vthib/boreal/pull/132).

#### Changed:

* The `bitmap` dependency has been removed and replaced by an custom implementation for our
  very limited usecase. [#120](https://github.com/vthib/boreal/pull/120).
* The `windows` dependency has been replaced by `windows-sys`.
  [#137](https://github.com/vthib/boreal/pull/137).
* All dependencies have been updated to their latest versions.

Thanks to @demoray for their contributions.

## [0.5.0] - 2024-02-16

This release mainly consists of Yara 4.5 compatibility features and fixes:

### boreal

#### Added:

YARA 4.5 support:

- New Warning on unknown escape sequences in regexes. See [PR #68](https://github.com/vthib/boreal/pull/68).
  This warning is more broad than the YARA one from YARA 4.5.
- always expose `pe.is_signed` [97d1d11](https://github.com/vthib/boreal/commit/97d1d11b8a30980906f1aa01e88da70d0fbd4da8)
- Do not report strings whose name starts with `_` as unused [1a8a8cd](https://github.com/vthib/boreal/commit/1a8a8cdf32dbde114afeb7cd558a62efe8d9527f)
- Add `pe.export_details[*].rva` field [7597d3f](https://github.com/vthib/boreal/commit/7597d3f6a227f9b45efa58562fb38a8722125bc2)
- `math.count` and `math.percentage` now returns an undefined value when given a
  value outside the `[0; 255]` range. [6a09ed2](https://github.com/vthib/boreal/commit/6a09ed23f61be1a0ff7d08a8ad00216fa5c05856)
- Imported dlls are ignored if the dll name is longer than 255 bytes [28f8626](https://github.com/vthib/boreal/commit/28f86267f9ed39fd7c5f2826d89796665bb7bda5)
- Fix endianness issue in `macho.magic` field, see the [Yara fix](https://github.com/VirusTotal/yara/pull/2041) [50d418d](https://github.com/vthib/boreal/commit/50d418d1d40fb2d6cc61d34d1d813a8e7b373783)
- filter imported functions with invalid name in pe module [5a0cb4e](https://github.com/vthib/boreal/commit/5a0cb4e22c24c6101e42cb9ae3f21377c7c47500)
- bump limit on number of listed export symbols in pe module to 16384 [98032b3](https://github.com/vthib/boreal/commit/98032b3d23b41650e84a5c56f594f33d8bbad8d4)

#### Changed:

- crc32-fast dependency updated to 1.4 [f1ae01a](https://github.com/vthib/boreal/commit/f1ae01af06b773e5dd3038199ccbcf3e57c67ed7)
- authenticode-parser dependency updated [e68dde7](https://github.com/vthib/boreal/commit/e68dde73a74b1a7c8e4a4e4939d86bfb0546e577)

#### Fixed:

- Exclude test assets in package [24ca838](https://github.com/vthib/boreal/commit/24ca83801b34b8e959d7c1bc11022409f1e9230d).
  This avoids having the package be flagged by antiviruses, as unfortunately, some of the binaries copied from the yara repository
  and used for testing seems trigger false positives.

## [0.4.0] - 2024-02-11

This release introduces process memory scanning, implemented on Windows, Linux and macOS. In addition,
different modes of scanning are available, documenting the exact semantics of scanning a process memory.
This allows picking a mode that is less surpresing and faster than the default mode which reproduces
YARA's behavior. See [`FragmentedScanMode`](https://docs.rs/boreal/latest/boreal/scanner/struct.FragmentedScanMode.html) for more details,
as well as the updated [updated benchmarks](/benches/README.md).

In addition, an API to scan fragmented memory is now available. This is the API which is used during
process scanning, and allows custom handling of which memory blocks to scan.

Finally, a few additional features have been added, including an API to mmap files to scan, and the ability
to get partial results when the scanning fails, for example due to a timeout.

### boreal

#### Added

- Process scanning API on linux, windows [#88](https://github.com/vthib/boreal/pull/88) and macOS [#110](https://github.com/vthib/boreal/pull/110).
- Different scanning modes for fragmented memory, including process memory [#101](https://github.com/vthib/boreal/pull/101)
- New `memmap` feature exposing API to open files to scan using `mmap`/`MapViewOfFile` [#76](https://github.com/vthib/boreal/pull/76)
- New `process` feature exposing API to scan process memory [#97](https://github.com/vthib/boreal/pull/97)
- Implementation of `console` module [fe89efb](https://github.com/vthib/boreal/commit/fe89efb299c0711c70d16f2fae8a795efd26098a)
- Add fragmented memory handling API [#82](https://github.com/vthib/boreal/pull/82)
- Add `ScanError` and return Result in scanning API [#83](https://github.com/vthib/boreal/pull/83)

#### Changed:

Public API:

- Update MSRV to 1.65 [1d5b005](https://github.com/vthib/boreal/commit/1d5b005297f4e5a7e54f079dfdcbd4100465f460)

Internal API:

- Rework raw variables matching [#77](https://github.com/vthib/boreal/pull/77)
- Compute match details on match [#78](https://github.com/vthib/boreal/pull/78)
- Simplify module evaluation [#80](https://github.com/vthib/boreal/pull/80)
- Rework internal Scanner/Evaluator API [#81](https://github.com/vthib/boreal/pull/81)
- Handle access to memory split in multiple fragments in modules [#103](https://github.com/vthib/boreal/pull/103)

CI:

- Add macos 12 x64 tests in CI [#109](https://github.com/vthib/boreal/pull/109)
- Add tests related to process scanning [#111](https://github.com/vthib/boreal/pull/111)

### boreal-cli

#### Added

- Handling of many flags to mirror the yara CLI tool [#102](https://github.com/vthib/boreal/pull/102).

  - `--scan-list` to specify a file listing the files to scan [9982c15](https://github.com/vthib/boreal/commit/9982c15f4a211d5c79a5c18a3cbb7bae24873a2b)
  - `-d` to define external symbols [c584d6a](https://github.com/vthib/boreal/commit/c584d6ae75258b5470dba462210753082e99c639)
  - `-e` to print the namespace of matching rules [4485352](https://github.com/vthib/boreal/commit/44853529afc99996681b7e05d9fab2a1ead635c8)
  - `-w` to disable warnings [f9077bf](https://github.com/vthib/boreal/commit/f9077bf1c7fa36629cbfbb5353138e9576c22092)
  - `-a` to specify a timeout [183d430](https://github.com/vthib/boreal/commit/183d430569b8b30a09dd4e031bb9e5d46ee635c5)
  - `-m` to print metadatas of matching rules [d44cfef](https://github.com/vthib/boreal/commit/d44cfefc555ad93338b53f0afde40b192de7dae7)
  - `-i` to filter matching rules by name [25a35f8](https://github.com/vthib/boreal/commit/25a35f83feabf3b66812cc90d0137be4c73ae4c8)
  - `--tag` to filter matching rules by tag in boreal-cli [cecaa7f](https://github.com/vthib/boreal/commit/cecaa7fad68ce13193bf9a65109cc7024137e897)
  - `-q` to disable console logs [ce64391](https://github.com/vthib/boreal/commit/ce643914ea4b1e40ed6c2d1614e53431e23a64ab)
  - `-g`, `-s` and `-L` to print details of the strings of matching rules [277f89f](https://github.com/vthib/boreal/commit/277f89f58ac488cb7a1ce3eaa5d82d252e664e3d)

- Launching a process scan when argument is interpreted as a PID [#100](https://github.com/vthib/boreal/pull/100)

- Flags to control process scanning behavior [#101](https://github.com/vthib/boreal/pull/101)

  - `--max-process-memory-chunk` to control the size of the memory chunks to scan from the process memory.
  - `--max-fetched-region-size` to control the maximum size of scanned chunks.
  - `--fragmented-scan-mode` to control the mode of scanning, see doc on [`FragmentedScanMode`](https://docs.rs/boreal/latest/boreal/scanner/struct.FragmentedScanMode.html).

#### Fixed

- Prevent prints to be interleaved when using threads [8ef0b57](https://github.com/vthib/boreal/commit/8ef0b575eb4ff6980d9fa6774c2fba6d6f06a2d6)

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

[unreleased]: https://github.com/vthib/boreal/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/vthib/boreal/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/vthib/boreal/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/vthib/boreal/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/vthib/boreal/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/vthib/boreal/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/vthib/boreal/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vthib/boreal/releases/tag/v0.1.0
