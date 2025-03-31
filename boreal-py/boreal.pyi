from typing import Any, Callable, Protocol, TypeAlias, TypedDict, final
from collections import abc


def compile(
    filepath: str | None = None,
    filepaths: dict[str, str] | None = None,
    source: str | None = None,
    sources: dict[str, str] | None = None,
    file: Readable | None = None,

    externals: dict[str, ExternalValue] | None = None,
    includes: bool = True,
    error_on_warning: bool = False,
    include_callback: IncludeCallback | None = None,
    strict_escape: bool | None = None,
    profile: CompilerProfile | None = None,
) -> Scanner: ...

def load(
    filepath: str | None = None,
    file: Readable | None = None,
    data: bytes | None = None,
) -> Scanner: ...

def set_config(
    max_strings_per_rule: int | None = None,
    max_match_data: int | None = None,
    stack_size: int | None = None,
    yara_compatibility: bool | None = None,
) -> None: ...

modules: list[str]
"""List of availables modules"""

class Error(Exception): ...
class AddRuleError(Error): ...
class SyntaxError(Error): ...
class ScanError(Error): ...
class TimeoutError(Error): ...


@final
class Rule:
    identifier: str
    namespace: str
    tags: list[str]
    meta: dict[str, MetadataValue]
    is_global: bool
    is_private: bool


@final
class Match:
    rule: str
    namespace: str
    meta: dict[str, MetadataValue]
    tags: list[str]
    strings: list[StringMatches]

    def __le__(self, other: object) -> bool: ...
    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __gt__(self, other: object) -> bool: ...
    def __ge__(self, other: object) -> bool: ...

    def __hash__(self) -> int: ...


@final
class Scanner(abc.Iterable[Rule]):
    warnings: list[str]

    def match(
        self,
        filepath: str | None = None,
        data: str | bytes | None = None,
        pid: int | None = None,
        externals: dict[str, ExternalValue] | None = None,
        callback: MatchCallback | None = None,
        # TODO: improve type
        which_callbacks: int | None = None,
        fast: bool | None = None,
        timeout: int | None = None,
        modules_data: dict[str, Any] | None = None,
        modules_callback: ModulesCallback | None = None,
        warnings_callback: WarningCallback | None = None,
        console_callback: ConsoleCallback | None = None,
        allow_duplicate_metadata: bool | None = False,
    ) -> list[Match]: ...

    def save(
        self,
        filepath: str | None = None,
        file: Writable | None = None,
        to_bytes: bool = False
    ) -> bytes | None: ...

    def set_params(
        self,
        use_mmap: bool | None = None,
        string_max_nb_matches: int | None = None,
        fragmented_scan_mode: str | None = None,
        process_memory: bool | None = None,
        max_fetched_region_size: int | None = None,
        memory_chunk_size: int | None = None,
    ) -> None: ...

    def __iter__(self) -> RulesIter: ...


@final
class RulesIter(abc.Iterator[Rule]):
    def __iter__(self) -> RulesIter: ...
    def __next__(self) -> Rule: ...


@final
class StringMatchInstance:
    offset: int
    matched_data: bytes
    matched_length: int
    xor_key: int

    def plaintext(self) -> bytes: ...

    def __hash__(self) -> int: ...


@final
class StringMatches:
    identifier: str
    instances: list[StringMatchInstance]

    def is_xor(self) -> bool: ...

    def __hash__(self) -> int: ...


@final
class RuleString:
    namespace: str
    rule: str
    string: str


@final
class CompilerProfile:
    Speed: 'CompilerProfile'
    Memory: 'CompilerProfile'


class RuleDetails(TypedDict):
    """Details about a rule passed to the match callback."""

    rule: str
    """Name of the matching rule"""
    namespace: str
    """Namespace of the matching rule"""
    meta: dict[str, MetadataValue]
    """List of tags associated to the rule"""
    tags: list[str]
    """Dictionary with metadata associated to the rule"""
    strings: list[StringMatches]
    """Details about the string matches of the rule"""
    matches: bool
    """Did the rule match"""


__version__: str
"""Version of the boreal-py library"""

CALLBACK_CONTINUE: int
"""Return value used in callbacks to signal the scan must continue.

Callbacks used in the [`match`](api.md#boreal.Scanner.match) method should return
this value to keep the scan going.
"""

CALLBACK_ABORT: int
"""Return value used in callbacks to abort the scan.

Callbacks used in the [`match`](api.md#boreal.Scanner.match) method should return
this value to abort the scan. If the scan is aborted, the match method will
not raise any exception but will end immediately, returning the results it
has computed so far.
"""

CALLBACK_MATCHES: int
"""Call the match callback when a rule matches.

If specified in the `which_callbacks` parameter of the
[`match`](api.md#boreal.Scanner.match) method, the callback will be
called when a rule matches.
"""

CALLBACK_NON_MATCHES: int
"""Call the match callback when a rule does not match.

If specified in the `which_callbacks` parameter of the
[`match`](api.md#boreal.Scanner.match) method, the callback will be
called when a rule does not match.
"""

CALLBACK_ALL: int
"""Call the match callback after a rule is evaluated.

If specified in the `which_callbacks` parameter of the
[`match`](api.md#boreal.Scanner.match) method the callback will be called
after a is evaluated, regardless of whether it has matched or not. the
[`matches`](api.md#boreal.RuleDetails.matches) attribute of the passed rule
can be used to know if the rule has matched or not.
"""

CALLBACK_TOO_MANY_MATCHES: int
"""A string has had too many matches.

This is used in the `warnings_callback` of the [`match`](#boreal.Scanner.match)
method to indicate the warning kind.
"""

CallbackResult: TypeAlias = int
"""Return status that can be returned by a callback.

This must be one of:

  - [`CALLBACK_CONTINUE`](api.md#CALLBACK_CONTINUE)

  - [`CALLBACK_ABORT`](api.md#boreal.CALLBACK_ABORT)
"""

WarningType: TypeAlias = int
"""Type of warning passed to the warning callback.

This can be one of:

  - [`CALLBACK_TOO_MANY_MATCHES`](api.md#boreal.CALLBACK_TOO_MANY_MATCHES):
    the associated data is a [`RuleString`](api.md#boreal.RuleString).
"""

ConsoleCallback: TypeAlias = Callable[[str], None]
"""Callback handling uses of the `console` module in rules.

It receives the log as the lone argument.
"""

MatchCallback: TypeAlias = Callable[[RuleDetails], CallbackResult]
"""Callback called when rules are evaluated."""

ModulesCallback: TypeAlias = Callable[[dict[str, Any]], CallbackResult]
"""Callback called when a module is evaluated.

The callback receives the dynamic values of the module as the first
argument. The name of the module is accessible with the `"module"` key.
"""

WarningCallback: TypeAlias = Callable[[WarningType, RuleString], CallbackResult]
"""Callback called when a warning is emitted during a scan."""

MetadataValue: TypeAlias = bytes | int | bool
"""The value of a metadata key declared in a rule."""

ExternalValue: TypeAlias = str | bytes | int | float | bool
"""The value of an external symbol usable in a rule condition."""

IncludeCallback: TypeAlias = Callable[[str, str | None, str], str]
"""Callback used to resolve include directives.

Receive three arguments:

  - The path being included.

  - The path of the current document. Can be None if the current
    document was specified as a string, such as when using the
    `source` or `sources` parameter.

  - The current namespace.

Must return a string which is the included document.
"""

class Readable(Protocol):
    """A readable object"""

    def read(self) -> str: ...

class Writable(Protocol):
    """A writable object"""

    def write(self, data: bytes) -> int: ...
    def flush(self) -> None: ...
