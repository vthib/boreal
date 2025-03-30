# Python bindings for the boreal YARA scanner

The library allows using the [boreal](https://github.com/vthib/boreal) library
to scan files and processes using YARA rules.

```py
import boreal

scanner = boreal.compile(source="""
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
""");

results = scanner.match(data=b"<\0t\0m\0p\0.\0d\0a\0t\0>\0")
assert [rule.name for rule in results] == ["example"]
```

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

For a description of all the differences that exists when the compatibility mode
is not enabled, you can consult [this documentation](https://vthib.github.io/boreal/boreal-py/dev/yara_compatibility_mode/).
