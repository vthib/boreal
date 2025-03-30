# YARA Compatibility details

By default, Boreal will have some differences with the YARA API on purpose:
the YARA API can have non ideal default behavior or have edge cases that
are not properly handled and can cause issues. However, the exact behavior
of the YARA module is accessible be setting the yara compatibility mode:

```py
import boreal

boreal.set_config(yara_compatibility=True)
```

If you are not migrating from the YARA API, you should just use the
default behavior of boreal and not enable this mode.

The list of the differences is documented below. If any of those is problematic
for you, you can either align with the boreal behavior, or enable the
yara compatibility mode.

## Fast mode by default

Fast mode is enabled by default instead of being opt-in. This enables several
optimizations, but means that results may not contain all possible match details.

```py
import boreal

rules = boreal.compile(source="...")
# No need to specify fast=True. `matches` will list all matching rules,
# but details on the string matches might be missing if the scan did not
# need to compute them to complete faster.
matches = rules.match(data="...")
```

## Strict escape on by default

The `strict_escape` parameter in the `compile` function defaults to `True`
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

## Better hash implementations

The `__hash__` implementation for the `StringMatches` and `StringMatchInstance`
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

## String identifiers are not prefixed by '$'

The `identifier` field in `StringMatches` is not prefixed by `$`.

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

## Textual metadata values are bytes

Text metadata values are returned as byte-strings instead of strings.

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

## Match callback only receive matching rules by default

If `which_callbacks` is not specified in the `match` method, the default value is
`CALLBACK_MATCHES` and not `CALLBACK_ALL`. This default value is almost always
what is expected, and enabling the collection of non matching rules disables
fast mode, making it undesirable.

```py
import boreal

def cb(rule):
    # This callback only receives matching rules
    pass

rules = boreal.compile(source="...")
matches = rules.match(data="...", callback=cb)
```

## Maximum number of matches is reduced

The maximum number of matches for a single string is much reduced
compared to the 1 000 000 set in yara. This avoids performance regressions
on strings matching too often. The default value is 1000, but this can easily
be modified:

```py
import boreal

rules = boreal.compile(source="...")
rules.set_params(string_max_nb_matches=100000)
```

## Dictionaries returned by modules uses byte-strings as keys

Dictionaries that are contained in module values returned in the modules_callback
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
