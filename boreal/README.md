# boreal

[![Build status](https://github.com/vthib/boreal/actions/workflows/ci.yml/badge.svg)](https://github.com/vthib/boreal/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/boreal.svg)](https://crates.io/crates/boreal)
[![Documentation](https://docs.rs/boreal/badge.svg)](https://docs.rs/boreal)

Boreal is an evaluator of [YARA](https://virustotal.github.io/yara/) rules, used to scan bytes for textual and
binary pattern, predominantly for malware detections.

Although it is quite young, it should already be usable in place of yara in many use cases.
See [missing features](#missing-features) for details on what is missing.

## Description

Boreal is designed to be a drop-in replacement of YARA, while also adding improvements.
The main goals of the project are:

* Complete compatibility with YARA rules
* Only pay for what you use
* Improved performances & reliability

## Features

* Full compatibility with YARA 4.2 and [most modules](#modules). Any existing rule can be used as is.
* Avoid scanning for strings when not required, greatly reducing execution time on carefully crafted
  rules. See [no scan optimization](#no-scan-optimization).
* Improved performances when using a few hundred rules. See the [benchmarks](/boreal/benches/README.md) for details.

  There is a lot of room to improve performances much more, as working on performances has not been the main focus yet.

## Installation & use

Boreal is available as a library and as a commandline tool.

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

let scanner = compiler.into_scanner();
let res = scanner.scan_mem(b"<\0t\0m\0p\0.\0d\0a\0t\0>\0");
assert!(res.matched_rules.iter().any(|rule| rule.name == "example"));
```

### Yara compatibility

Boreal guarantees that all rules that are valid and can be run by YARA will be accepted
and will exhibit the same behavior. This is guaranteed by the execution of the tests from
the YARA repository as well as the addition of many other tests, all of which are run both
on boreal and YARA to guarantee the exact same behavior.

There are however, some exceptions to this compatibility:

* Evaluation bugs. Boreal may not suffer from some of them, or may has already fixed some of them.
  For example, there are many bugs that are already fixed in boreal and YARA, but have not yet
  been released by YARA, so even though boreal supports YARA 4.2, some bugs are fixed in boreal
  and not in YARA.

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

- [x] elf
- [x] hash (with the _hash_ feature)
- [x] math
- [x] macho (with the _object_ feature)
- [x] pe (with the _object_ feature)
  - `pe.signatures` is behind the _openssl_ feature
  - `pe.imphash()` is behind the _hash_ feature
- [x] time

Modules not yet supported:

- [ ] cuckoo
- [ ] dex
- [ ] dotnet
- [ ] magic
- [ ] console

## Missing Features

A few key features are still missing. If you are looking into using boreal in place of YARA,
some of those might be blockers for you:

#### Optimizations

A few optimizations were done, mostly to have acceptable performances. However, there is still a
lot that is planned and yet to be done. As can be seen in the [benchmarks](/boreal/benches/README.md),
huge number of rules, big files and bad hex or regex strings deteriorates performances quite a lot.
This is mainly because of missing optimizations that is planned in the next releases.

#### Defensive programming and protection against all possible rules.

For now it is possible to craft rules that will cause stack overflows or behave badly in general.
If you control the origin of all of your rules, this is not an issue. If that is not the case
however, you shouldn't use boreal yet. This is in active development.

#### Process scanning

Only scanning files or bytes is available for the moment.

#### Configurable timeout on scan

Closely related to defensive programming, and will probably be implemented at the same time.

#### Missing modules

See the module list [above](#modules). This will greatly depend on declared interest,
as I'm unsure how often those are used. If you would like to use boreal but a module that you
need is not implemented, please create an issue.

#### Saving and loading compiled rules

I am not quite sure what are the use-cases for this YARA feature, as the compilation of YARA rules
is not that time consuming. Please create an issue with a use-case if this is a feature you would
need.

#### Using mmap/MapViewOfFile to avoid duplicating the scanned file in memory.

This is unfortunately not done because of the trickiness of doing this properly in Rust, as reading
of a file mapping can trigger signals (SIGBUS) or exceptions. I hope to have a solution for
this in the future.

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

## Other optimizations

Another optimization that is planned but not ready yet include slimmed down modules, where for
example depending on the `pe` module to only use `pe.is_dll()` should not trigger the computation
of all signatures, imports, exports, resources, etc on every scan.

## crate feature flags

- `hash`: adds dependencies to compute hashes, enables the `hash` module and the `pe.imphash()` function
  if the `object` feature is also enabled.
- `object`: add dependencies to parse object files, enables the `elf`, `macho` and `pe` module.
- `openssl`: add dependency on openssl, enables the `signatures` part of the `pe` module.

By default, `hash` and `object` are enabled, `openssl` is not.
