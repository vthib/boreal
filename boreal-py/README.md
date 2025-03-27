# Python bindings for the boreal YARA scanner.

The library allows using the [boreal](https://github.com/vthib/boreal) library
to scan files and processes using YARA rules.

## Description

This library can serve as a drop-in replacement of the YARA python library,
while also providing improvements and saner default behavior.

- Literal replacement to the yara library:
  replace `import yara` with `import boreal` and everything will work.

- Saner default behavior compared to the yara library: fast scanning enabled
  by default, proper hash implementations of python objects, use of the bytes
  type in some places to avoid losing information, etc.

- 100% compatibility with the yara library guaranteed if needed through
  a yara compatibility mode.

## Yara compatibility

This library guarantees 100% compatibility with the YARA library: the whole API
is entirely tested against both libraries to guarantee perfect compatibility.

However, a few differences are introduced in the default behavior of this library
to ensure that this default behavior fixes some issues in the behavior of the yara
library. Those changes are minimal, but can introduce breakage when replacing
the yara library.

Therefore, you can either:

- Use the compatibility mode to ensure 100% compatibility with the yara library:

```py
import boreal

boreal.set_config(yara_compatibility=True)
```

This guarantees that the yara library can be replaced and nothing will break.
However, it also keeps alive a few issues in this library. It is therefore
only recommended to enable this mode when replacing the yara library and wanting
to ensure that nothing can break.

- Use boreal as is. This fixes a few issues while still providing almost
  entirely the same API.

This is recommended if using this library from scratch, or when all the uses
of the yara library can be easily checked to ensure nothing will break.

### Differences

If the yara compatibility mode is not enabled, the following differences
exist with the yara library:

- Fast mode is enabled by default instead of being opt-in. This enables several
  optimizations, but means that results may not contain all possible match details.

```py
import boreal

rules = boreal.compile(source="...")
# No need to specify fast=True. `matches` will list all matching rules,
# but details on the string matches might be missing if the scan did not
# need to compute them to complete faster.
matches = rules.match(data="...")
```

- The `strict_escape` parameter in `boreal.compile()` defaults to `True`
  instead of `False`. This means that rules that contain invalid escaping
  in regexes produce warnings by default.

```py
import boreal

rules = boreal.compile(source="""
rule foo {
    strings:
        $ = /C:\Users/
    condition:
        any of them
}
""")
# A warning is emitted by default, as opposed to yara
assert len(rules.warnings) == 1
```

- The `__hash__` implementation for the `StringMatches` and `StringMatchInstance`
  objects is improved to avoid collision issues. Those objects are returned
  in a scan result:

```py
import boreal

rules = boreal.compile(source="...")
results = rules.match(data="...")
rule_match = results[0]
string_matches = rule_match.strings[0] # This is StringMatches
string_instances = string_matches.instances[0] # This is StringMatchInstance
```

- The `identifier` field in `StringMatches` is not prefixed by `$`.

```py
import boreal

rules = boreal.compile(source="""
rule foo {
    strings:
        $mystr = "abc"
    condition:
        any of them
results = rules.match(data="abc")
rule_match = results[0]
string_matches = rule_match.strings[0]
assert string_matches.identifier == "mystr"  # as opposed to "$mystr" in yara
```

- Text metadata values are returned as bytestrings instead of strings.

```py
import boreal
    rules = module.compile(source="""

rule a {
    meta:
        foo = "a normal string"
        bar = "a string with non ascii bytes: \\xCA\xFE"
    condition: true
}""")
matches = rules.match(data='')
assert matches[0].meta == {
    'foo': b'a normal string'
    'bar': b'a string with non ascii bytes: \xCA\xFE' # yara does not return this properly
}
```

- The maximum number of matches for a single string is much reduced
  compared to the 1 000 000 set in yara. This avoids performance regressions
  on strings matching too often.

TODO example

- Dictionaries that are contained in module values returned in the modules_callback
  uses bytestrings as keys instead of strings. This can happen for example in the
  `pe.version_info` dictionary:

```py
rules = boreal.compile(source="""
import "pe"
rule a { condition: true }
""")

    def modules_callback(values):
        assert values['version_info'][b'InternalName'] == b'MTXEX.DLL'
        # This is ['version_info']['InternalName'] in yara

    rules.match('mtxex.dll', modules_callback=modules_callback)
```

  This is required because those keys are not guaranteed to be strings.
  There is [a known bug](https://github.com/VirusTotal/yara-python/issues/273) in
  yara due to this: if a dictionary key is not a proper string, the scan will fail.
