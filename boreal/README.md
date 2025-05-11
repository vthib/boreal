# boreal

[![Build status](https://github.com/vthib/boreal/actions/workflows/ci.yml/badge.svg)](https://github.com/vthib/boreal/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/boreal.svg)](https://crates.io/crates/boreal)
[![Documentation](https://docs.rs/boreal/badge.svg)](https://docs.rs/boreal)
[![Coverage](https://codecov.io/gh/vthib/boreal/branch/master/graph/badge.svg?token=FVI7Z45KFW)](https://codecov.io/gh/vthib/boreal)

Boreal is an evaluator of [YARA](https://virustotal.github.io/yara/) rules, used to scan bytes for textual and
binary pattern, predominantly for malware detections.

## Description

Boreal is designed to be a drop-in replacement of YARA, while also adding improvements.
The main goals of the project are:

* Complete compatibility with YARA rules
* Only pay for what you use
* Improved performances & reliability

## Features

* Full compatibility with YARA 4.5.2 and all [official modules](#modules). Any existing rule can be used as is.
* Avoid scanning for strings when not required, greatly reducing execution time on carefully crafted
  rules. See [no scan optimization](#no-scan-optimization).
* Protection against any untrusted inputs, be it rules or scanned bytes. Ill-crafted rules or inputs should never
  lead to a crash or deteriorated performances.
* Improved performances in most cases, especially when using a few hundred rules.
  See the [benchmarks](/benches/README.md) for details.
* Process scanning on Windows, Linux and macOS, with different scanning modes available. See the
  [FragmentedScanMode documentation](https://docs.rs/boreal/latest/boreal/scanner/struct.FragmentedScanMode.html).
* Rules can be optimized for different situations, by prioritizing either scanning speed or memory consumption.
* Pure Rust implementation without any C dependency such as OpenSSL, making it very easy to build and use
  on any target. The only exception is the magic module which requires libmagic.
* All YARA features are supported. This includes all the official modules, serialization into bytes, etc.

## Installation & use

Boreal is available:

- as a rust library, providing all of the features and configurations available in libyara and some additional ones.
- as a commandline tool, which reproduces the same flags and invocations as the yara CLI tool. It can thus replace
  as is the yara CLI tool.
- as a python library, which reproduces with 100% compatibility the API and objects of the yara python library.
  See the [python library documentation](https://vthib.github.io/boreal/boreal-py/dev/)  for more details.

The commandline tool can be built from source:

```bash
> cargo install --locked boreal-cli
```

And uses the same flags and syntax as the yara executable:

```bash
> ./boreal path/to/rules path/to/dir
rule_1 path/to/dir/suspicious_file
```

Boreal can also be used as a library, please take a look at the [documentation](https://docs.rs/boreal).

The API should feel familiar if you ever used YARA or Yara-Rust as a library:

```rust
use boreal::Compiler;

let mut compiler = Compiler::new();
compiler.add_rules_str(r#"
rule example {
    meta:
        description = "This is an YARA rule example"
        date = "2022-11-11"
    strings:
        $s1 = { 78 6d 6c 68 74 74 70 2e 73 65 6e 64 28 29 }
        $s2 = "tmp.dat" fullword wide
    condition:
        any of them
}
"#)?;

let scanner = compiler.finalize();
let res = scanner.scan_mem(b"<\0t\0m\0p\0.\0d\0a\0t\0>\0");
assert!(res.matched_rules.iter().any(|rule| rule.name == "example"));
```

### Yara compatibility

Boreal guarantees that all rules that are valid and can be run by YARA will be accepted
and will exhibit the same behavior. This is guaranteed by the execution of the tests from
the YARA repository as well as the addition of many other tests, all of which are run both
on boreal and YARA to guarantee the exact same behavior.

There are however, some exceptions to this compatibility:

* Overflows or underflows. Those are not specified by YARA and in fact, signed overflows is UB in
  itself. Behavior of evaluations on overflows/underflows is no longer UB in boreal, but is
  for the moment not specified.

* Defensive limits on adversarial rules. Boreal sets limits to ensure it is impossible to write
  rules that can cause issues in a program parsing or evaluating this rule. Although those limits
  do technically reject rules that YARA would accept, those limits should never impact proper
  rules.

In addition, there is for the moment a single evaluation difference between YARA and boreal:

* A rule that depends on itself no longer compiles.

```yara
rule my_rule {
    condition: my_rule
}
```

In YARA, this is valid, and will always evaluate to false. In Boreal, this rule does not compile.

There are no plans to fix this behavior, as I don't see a valid usecase for it, and fixing it is not
free. If however someone can provide a valid use-case, this difference can be resolved.

#### Modules

- [x] elf (with the _object_ feature)
- [x] hash (with the _hash_ feature)
- [x] math
- [x] macho (with the _object_ feature)
- [x] pe (with the _object_ feature)
  - `pe.imphash()` is behind the _hash_ feature
  - `pe.signatures` is behind the _authenticode_ feature
  - `pe.is_signed` and the signatures `verified` value is behind the _authenticode-verify_ feature,
    disabled by default. See the [authenticode-verify](#authenticode-verify) section for more details.
- [x] dotnet (with the _object_ feature)
- [x] string
- [x] time
- [x] console
- [x] dex (with the _object_ feature)
- [x] magic (with the _magic_ feature, disabled by default)
- [x] cuckoo (with the _cuckoo_ feature, disabled by default)

## Pay for what you use

YARA is an amazing software that is however mainly designed to optimize for the worst case
scenario. This leads to a lot of useless and unnecessary work, and makes it very frustrating for
a user that designs rules that should be really fast to evaluate.

### No scan optimization

Lets say you write this rule:

```yar
rule should_be_fast {
    strings:
        $a = { 10 2d EF CF 29 31 26 }
    condition:
        filesize < 50KB and $a
}
```

You would expect that scanning this rule against a big directory would be quite fast, as all big
files would be skipped, without a need to scan the whole contents of all the files.

This is however, not what happens with YARA. With boreal however, all files that are bigger than
50KB will not be scanned, and evaluation of this rule will be very fast.

This optimization applies as long as all rules can be evaluated without needing to scan for their
strings. If a single rule needs a scan, then all strings of all rules will be scanned.

There are still some work to do on this. For example, the common "$a at X" rule is not yet
properly handle and will require a scan for the string. If you think you have a rule that should
not require scanning but does, please report it.

## Crate feature flags

### Enabled by default

- `object`: enables the `elf`, `macho`, `pe`, `dotnet` and `dex` modules.
- `hash`: enables the `hash` module, as well as the `pe.imphash()` function if the `object`
  feature is also enabled.
- `authenticode`: enables the `signatures` part of the `pe` module.
- `process`: adds the process scanning API.
- `memmap`: adds APIs to scan files using memory maps.

### Disabled by default

- `profiling`: adds computations of statistics during compilation and evaluation.
- `magic`: enables the `magic` module. Adds a dependency on libmagic.
- `cuckoo`: enables the `cuckoo` module.
- `authenticode-verify`: enables the `pe.signed`, `pe.signatures[*].verified` and
  `pe.signatures[*].countersignatures[*].verified` part of the `pe` module.
- `serialize`: enables the API to save a scanner into bytes and reload them on
   another computer. Note that to make this feature work, some additional data
   must be saved in the scanner, which is not saved if the feature is disabled.
   This overhead will depend on the type of rules used, but is usually between
   a 2 to 6% increase. It it thus recommended to not enable this feature if
   serialization is not needed.
   See the [benchmarks](/benches/README.md#cost-of-serialize-feature) for details.

### `authenticode-verify`

YARA 4.3 introduced new parsing for the `pe.signatures` object, and notably the
fields `pe.is_signed`, `pe.signatures[*].verified` and `pe.countersignatures[*].verified`.
Those fields however causes a few issues:

- They can be confusing, as they do not indicate whether Windows would actually
  consider the file as signed, as their is no trust anchor verification.
- They bring a dependency to OpenSSL to do the signature verification, and any
  equivalent implementation would imply bringing a lot of dependencies to handle
  all the different algorithms that can be used in signatures.

I'm unsure what the use-case for those fields are, so they are not implemented by
default. To be able to use them, there are two possibilities:

- the `authenticode-verify` feature can be enabled to get them back, but the implementation
  is best effort. It does not depend on OpenSSL but uses rust cryptos crates, so not
  all algorithms are implemented, and some checks might be missing.
- on Windows, `WinVerifyTrust` can be called and the result provided as an external symbol.
  A feature can be implemented to make this available as `pe.is_signed` instead of an
  external symbol, but I would like to judge interest in this before implementing it.
  The benefit here, is that the value truly reflects whether the file is considered as
  signed or not by Windows.

If you need to use those fields and those solutions are not sufficient, please open an issue.
