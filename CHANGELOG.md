# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- Python bindings have been added, and are available through the `boreal-python` pypi package.
  Those bindings provide a "yara compatibility" mode with full compatibility with the yara
  python bindings, allowing seamless transition from it.

- The `boreal` CLI tool has been reworked and completed. It now supports all options from
  the `yara` CLI tool (except `--atom-quality-table`) and provides a "yara compatibility"
  mode through the use of the `yr` subcommand, allowing seamless transition from it.

- A scanner can now be serialized into bytes (and deserialized) through the `serialize`
  feature. This is the equivalent of the yara save/load API. This however increases the
  scanner size by a few percent, and has a lot of caveats linked to it. See the
  [`Scanner::to_bytes`](https://docs.rs/boreal/latest/boreal/scanner/struct.Scanner.html#method.to_bytes)
  for more details.

- All scanning APIs now have a variant that uses a callback. This callback will be called
  on specific events: when a rule matches, when a module is imported, etc.
  [`scanner::ScanEvent`](https://docs.rs/boreal/latest/boreal/scanner/struct.ScanEvent.html)
  for more details.

- Several more features have been added: modifying the include callback, limiting the
  number of strings per rule, etc. See the changelog below for details.

- The benchmarks have been reworked: `YARA-X` have been added to it and benchmarks on
  the serialize feature have been added.

Since this is the first stable release, several breaking changes have been done to stabilize
the API. See the breaking changes list just below.

### boreal

Breaking changes:

- The `Compiler::into_scanner` method has been renamed to `Compiler::finalize`
  [#226](https://github.com/vthib/boreal/pull/226).
- The `namespace` field for rules is now non optional, and the default namespace is named
  `"default"`. This means that if you previously added rules in the default namespace and
  rules in a custom namespace named `"default"`, this would now add to the same namespace
  and may conflict. This aligns the logic on what yara does and simplifies compatibility
  [4ffca07](https://github.com/vthib/boreal/commit/4ffca07ab352f6c5bd687d00ddbef41bb5291baf)
- The `ScanResult::statistics` field is now boxed. This reduces the size of the
  object greatly.
- The `ScanResult::module_values` field has been replaced by `ScanResult::modules`, which
  also returns a pointer to the modules, allowing access to their static values
  [#225](https://github.com/vthib/boreal/pull/225).
- `boreal::scanner::MatchedRule` has been renamed to `boreal::scanner::EvaluatedRule`
  [979f162](https://github.com/vthib/boreal/commit/979f162fe9b6d703e7ca1158961eb24255aa1c32).
- `boreal::Compiler::default` has been removed, use of the `CompilerBuilder` object
  is mandatory to customize which modules are enabled
  [586be27](https://github.com/vthib/boreal/commit/586be27d9e6ceb37dab0fe2ea1f55cc847db2de0).
- Bump MSRV to 1.74
  [928e380](https://github.com/vthib/boreal/commit/928e3806668267f2d8e90d5a5ca631b760e462a3).
- `boreal::scanner::StringMatch::data` has changed from a `Vec<u8>` to a `Box<[u8]>`
  to reduce the memory size of this object
  [928e380](https://github.com/vthib/boreal/commit/928e3806668267f2d8e90d5a5ca631b760e462a3).
- `boreal::compiler::AddRuleError` no longer has a `to_short_description` method. Instead,
  this object implements `std::fmt::Display` which can be used to generate the same short
  description
  [6658ebb](https://github.com/vthib/boreal/commit/6658ebb0c5351361d81c3d0bf75ff8e5935218e7).

#### Added

- Added callback based API variants for all `Scanner::scan_*` methods. For example,
  `Scanner::scan_mem_with_callback`, `Scanner::scan_process_with_callback`. This
  callback can receive several type of events, and is able to abort the scan during
  any received event. See `boreal::scanner::ScanEvent` and `boreal::scanner::CallbackEvents`
  for more details on the types of events handled
  [#187](https://github.com/vthib/boreal/pull/187).
- Added `serialize` feature to serialize a `Scanner` object into bytes which can be
  deserialized on another computer. See `Scanner::to_bytes` for more details.
  [#203](https://github.com/vthib/boreal/pull/203).
- Added ability to customize include behavior with a callback used during compilation.
  See `Compiler::set_include_callback` for more details
  [637dece](https://github.com/vthib/boreal/commit/637deceedf9657ac8a1aa9c6766cb7acc068caf0).
- Added scan parameters to include not matched rules in results
  [8a951d8](https://github.com/vthib/boreal/commit/8a951d8fc0d4a09d58016044049368ab94cc330c).
- Callback for console module can now be provided in the scanner rather than
  during compilation
  [3522484](https://github.com/vthib/boreal/commit/3522484ea9a08770fe702f7efce7482ff70134f8).
- Added `Scanner::rules` to iterate over the rules contained in a scanner
  [68ee69b](https://github.com/vthib/boreal/commit/68ee69bc7f80d9862bb83c383bc78922c53eb5a3).
- Added `max_strings_per_rule` compilation parameter to fail compilation if a rule contains
  too many rules
  [696ce79](https://github.com/vthib/boreal/commit/696ce79549013a3caf33cc7b13329b93fc94a19b).
- Added `xor_key` field in `boreal::scanner::StringMatch` to indicate which xor key was used
  on a given match
  [7c9fd27](https://github.com/vthib/boreal/commit/7c9fd2720e3a8af315f9ff986cae02b2702ec05c).
- Added `has_xor_modifier` field in `boreal::scanner::StringMatches`
  [6853938](https://github.com/vthib/boreal/commit/6853938e60066649cabd406e2db559393a3d1209).
- Implement `std::fmt::Display` and `std::error::Error` on `boreal::compiler::AddRuleError`.
  This means this is now a real Error object and the `AddRuleError::to_short_description`
  method no longer needs to be called to generate a description for the error
  [6658ebb](https://github.com/vthib/boreal/commit/6658ebb0c5351361d81c3d0bf75ff8e5935218e7).

#### Updated

- update codespan-reporting to 0.12
  [2b7f394](https://github.com/vthib/boreal/commit/2b7f394e47ba13121876bfc29c29740ab144a659)
- update to nom 8.0
  [d62db91](https://github.com/vthib/boreal/commit/d62db91896abaa44733ffce26961922926308c85)

### boreal-cli

See [the boreal-cli CHANGELOG file](boreal-cli/CHANGELOG.md#1.0.0).

## [0.9.0] - 2024-10-11

This release brings several memory optimizations and small API improvements.

Memory optimizations comes in two forms:

- Generic optimizations to reduce the memory footprint of compiled rules, useful in all
  cases when the `Scanner` object is kept for a long time.
- The introduction of a new profile that can be set in the compiler, which will compile
  rules to optimize for memory usage rather than scanning speed.

### boreal

Breaking changes:

- A memory pool was introduced to greatly reduce the memory footprint of compiled rules,
  notably when the same meta strings are used in all rules. This introduces two breaking
  changes:

  - The `Metadata` and `MetadataValue` objects are no longer re-exported from `boreal-parser`
    but are new types.
  - To retrieve strings and byte-strings from those objects, the new `Scanner::get_bytes_symbol`
    and `Scanner::get_string_symbol` must be used.

- A new `CompilerBuilder` object is introduced, to be able to configure a `Compiler` before
  any rule is added.

- Added `UnwindSafe` and `RefUnwindSafe` trait bounds on module datas:

  - add UnwindSafe traits to module private datas [43502307](https://github.com/vthib/boreal/commit/435023079dd260622a2ed82424b1d2dc3830487d)
  - add UnwindSafe traits for module user datas [56111d77](https://github.com/vthib/boreal/commit/56111d772bd3b754f2371a46c01523fb601e96fe)

- MSRV is bumped from 1.65 to 1.66 [825aaab](https://github.com/vthib/boreal/commit/825aaab4f46afbe46d218d7bc92ae970ab15746e)

#### Added

- Add CompilerBuilder object to add modules and configure compiler profile: [261b11c2](https://github.com/vthib/boreal/commit/261b11c2228d1b28401ee5b3c3ce323a08c41e35)
- Add compiler profile to pick between memory usage or scanning speed: [#167](https://github.com/vthib/boreal/pull/167).
- Add compiler param to disable includes: [#170](https://github.com/vthib/boreal/pull/170).
- Update compatibility with YARA 4.5.2: [#172](https://github.com/vthib/boreal/pull/172).

#### Changed

- Add bytes intern pool to reduce memory consumption: [#165](https://github.com/vthib/boreal/pull/165).
- Guarantee `Scanner` is `UnwindSafe` and `RefUnwindSafe`: [#171](https://github.com/vthib/boreal/pull/171).
* Update memory benchmarks [68a1e046](https://github.com/vthib/boreal/commit/68a1e046018ef3232dcf6f3cc4c04f5c5fac8898)
- Update windows-sys dependency to version 0.59 [ff996f77](https://github.com/vthib/boreal/commit/ff996f7707abd65ac6d3f86066872c18c5ee4db7)
- Update tlsh2 dependency to version 0.4.0 [29097dc8](https://github.com/vthib/boreal/commit/29097dc85eb5122dea9a6876c03edf350c6fc1fd)

#### Fixed

- Fix unused warning on statistics in default features config: [#168](https://github.com/vthib/boreal/pull/168).

### boreal-cli

#### Added

- Added option `--profile` to select memory or speed profile: [c3a89c29](https://github.com/vthib/boreal/commit/c3a89c29dca947e455e597dfc0798506bc2943ab).

## [0.8.0] - 2024-06-09

This release consists of several changes to make the library easier to use in any context
or target:

- The dependency on OpenSSL (through the `authenticode` feature) is removed and replaced
  by pure-Rust dependencies, through the use of two features:

  - The `authenticode` feature is retained but is now enabled by default. It uses two
    new dependencies to parse the authenticode signatures.
  - A new `authenticode-verify` feature is added to handle the `pe.is_signed`,
    `pe.signatures[*].verified` and `pe.signatures[*].countersignatures[*].verified` fields.
    See the [dedicated documentation](/boreal/README.md#authenticode-verify) for details.

- The patched version of `object` has been removed, making the use of the library much
  easier.

Those changes make `boreal` depend only on Rust libraries (except for the `magic` feature),
which means the library can be used with any targets and is much easier to integrate.

In addition, this release brings full compatibility with YARA 4.5.1.

### boreal

#### ⚠  Breaking changes

- The `authenticode` feature has been revamped. It is now split into two features:

  - The `authenticode` feature, which implements all the `pe.signatures` field except the
    ones related to signature verification. This feature is now enabled by default.
  - The `authenticode-verify` feature, which implements the `pe.is_signed` and `*.verified` fields.
    This feature is disabled by default. See the [dedicated documentation](/boreal/README.md#authenticode-verify) for details.

- The `Compiler` API has been reworked to remove all the ugly workarounds that were needed due to
  the unsafety brought by the OpenSSL dependency. The `Compiler::new_with_pe_signatures` and
  `Compiler::new_without_pe_module` functions has been removed.

#### Added

- add authenticode-verify feature for signature verification [9ced02bf](https://github.com/vthib/boreal/commit/9ced02bf5ca04747cf741efb9ce6fb56e341814d).

#### Changed

- Remove `hex` dependency [bb46e49e](https://github.com/vthib/boreal/commit/bb46e49e5d23c0862b500e0da6fc26977786de11)
- Remove `object` patched version [#159](https://github.com/vthib/boreal/pull/159).
- Replace authenticode-parser dependency with a custom impl [f9521c5c](https://github.com/vthib/boreal/commit/f9521c5c001c43ed3b9b01cbd7d7085a96df2eda)
- Remove authenticode-parser dependency and clean API [21c5cd74](https://github.com/vthib/boreal/commit/21c5cd74ef2f586dfd8d115d20fb5647e4746f21)
- Enable hash dependencies when authenticode feature is enabled [b88fedb6](https://github.com/vthib/boreal/commit/b88fedb627d68ef349f22b2ce0022031b1ef2446)

YARA 4.5.1 compatibility:

- only consider valid ascii bytes for pe dll names [c219245e](https://github.com/vthib/boreal/commit/c219245e03fe79bebfe5dde6c5f0846a1a16dc6d).
- add some safety checks in pe module for corrupted values [00235005](https://github.com/vthib/boreal/commit/002350059c105152105e6398d2505f35136f1da5)
- update rva resolution in pe module [66c2d5f4](https://github.com/vthib/boreal/commit/66c2d5f4795e5b336e01942b8fa48cbbfe79d6cc)
- list dotnet resources that are not located in the file [b2fa436d](https://github.com/vthib/boreal/commit/b2fa436d7460cd7bfe7a68aa2561e5c11bdf3a10)

#### Fixed

- limit size of version info key and value in pe module [4a20f5c4](https://github.com/vthib/boreal/commit/4a20f5c417ee5b8ac165863fdec4cd4014650912)
- fix parsing issues in version_info of pe module [8c00218a](https://github.com/vthib/boreal/commit/8c00218a4e370761e6f8c20cb9189478afcbf268)

## boreal-parser 0.6.0 - 2024-06-09

#### Added

- Allow spaces in regex repetitions, eg `a{2 , 3}` [449c5fc4](https://github.com/vthib/boreal/commit/449c5fc4d95a30a05ea5b3dc62512de112d3e00a).
  This is a new feature introduced in YARA 4.5.1

## [0.7.0] - 2024-05-05

This release adds the last missing modules from YARA: `magic`, `dex` and `cuckoo`.
It also fixes some bugs related to the use of global rules.

### boreal

#### Added:

* The `magic` module is now available behind the `magic` feature (not enabled by default).
  [#139](https://github.com/vthib/boreal/pull/139).
* The `dex` module is now available behind the `object` feature (enabled by default).
  [#141](https://github.com/vthib/boreal/pull/141).
* The `cuckoo` module is now available behind the `cuckoo` feature (not enabled by default).
  [#143](https://github.com/vthib/boreal/pull/143), [#144](https://github.com/vthib/boreal/pull/144).

#### Fixed:

- Fix evaluation bug when global rules were declared after non-global rules.
  [#146](https://github.com/vthib/boreal/pull/146).
  If the global rules had any strings, it would make the evaluation of the
  rules that followed it invalid.
- Fix application of global rules to namespaces.
  [#147](https://github.com/vthib/boreal/pull/147), [#149](https://github.com/vthib/boreal/pull/149).
  Global rules were applied to all namespaces instead of only their own namespaces.

#### Changed:

* The type of `boreal::module::StaticValue::Function` and of the callback
  declared in the `console` module has changed from `Arc<Box<...>>` to `Arc<...>`.
  [#142](https://github.com/vthib/boreal/pull/142).
* Error reporting has been improved on IO error on the rules file.
  [#140](https://github.com/vthib/boreal/pull/140).

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

[unreleased]: https://github.com/vthib/boreal/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/vthib/boreal/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/vthib/boreal/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/vthib/boreal/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/vthib/boreal/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/vthib/boreal/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/vthib/boreal/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/vthib/boreal/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/vthib/boreal/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/vthib/boreal/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vthib/boreal/releases/tag/v0.1.0
