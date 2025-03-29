from typing import Callable, Protocol, TypeAlias
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
    # TODO: type the return value correctly
    include_callback: Callable[[str, str | None, str], int] | None = None,
    strict_escape: bool = None,
) -> Scanner: ...

modules: list[str]

class AddRuleError(Exception): ...
class SyntaxError(Exception): ...
class ScanError(Exception): ...
class TimeoutError(Exception): ...

class Rule:
    identifier: str
    namespace: str
    tags: list[str]
    meta: list[Metadata]
    is_global: bool
    is_private: bool


class Match(abc.Hashable):
    rule: str
    namespace: str
    meta: list[Metadata]
    tags: list[str]
    strings: list[StringMatches]

    def __le__(self, other: Match) -> bool: ...
    def __eq__(self, other: Match) -> bool: ...
    def __ne__(self, other: Match) -> bool: ...
    def __gt__(self, other: Match) -> bool: ...
    def __ge__(self, other: Match) -> bool: ...


class Scanner(abc.Iterable[Rule]):
    def __iter__(self) -> RulesIter: ...
    def match(
        filepath=None,
        data=None,
        pid=None,
        externals=None,
        callback=None,
        fast=None,
        timeout=None,
        modules_data=None,
        modules_callback=None,
        warnings_callback=None,
        which_callbacks=None,
        console_callback=None,
        allow_duplicate_metadata=None,
    ) -> list[Match]: ...
    def save(
        filepath: str | None = None,
        file: None = None,
    ) -> None: ...

    warnings: list[str]


class RulesIter(abc.Iterator[Rule]):
    def __iter__(self) -> RulesIter: ...
    def __next__(self) -> Rule | None: ...


class StringMatchInstance(abc.Hashable):
    offset: int
    matched_data: bytes
    matched_length: int
    xor_key: int

    def plaintext(self) -> bytes: ...


class StringMatches(abc.Hashable):
    identifier: str
    instances: list[StringMatchInstance]

    def is_xor(self) -> bool: ...

# Names in __all__ with no definition:
#   load
#   set_config

""" Version of the library """
__version__: str
""" Used as a return value in callbacks during scanning to continue the scan """
CALLBACK_CONTINUE: int
""" Used as a return value in callbacks during scanning to abort the scan """
CALLBACK_ABORT: int


CALLBACK_MATCHES: int
CALLBACK_NON_MATCHES: int
CALLBACK_ALL: int
CALLBACK_TOO_MANY_MATCHES: int

Metadata: TypeAlias = dict[str, MetadataValue]
MetadataValue: TypeAlias = bytes | int | bool
ExternalValue: TypeAlias = str | bytes | int | float | bool

class Readable(Protocol):
    def read() -> str: ...

class Writable(Protocol):
    def write(data: bytes) -> int: ...
    def flush() -> None: ...
