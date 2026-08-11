"""Deep immutable containers for public knowledge-system values."""

from __future__ import annotations

from collections.abc import Iterable
from collections.abc import Mapping
from typing import TypeVar
from typing import cast

from typing_extensions import Never
from typing_extensions import override


_Key = TypeVar("_Key")
_Value = TypeVar("_Value")


class FrozenDict(dict[_Key, _Value]):
    """A JSON-serializable dictionary that rejects every mutation method."""

    @override
    def __setitem__(self, _key: _Key, _value: _Value) -> Never:
        """Reject item assignment."""
        raise TypeError("FrozenDict is immutable")

    @override
    def __delitem__(self, _key: _Key) -> Never:
        """Reject item deletion."""
        raise TypeError("FrozenDict is immutable")

    @override
    def clear(self) -> Never:
        """Reject clearing."""
        raise TypeError("FrozenDict is immutable")

    @override
    def pop(self, *_args: object, **_kwargs: object) -> Never:
        """Reject keyed removal."""
        raise TypeError("FrozenDict is immutable")

    @override
    def popitem(self) -> Never:
        """Reject arbitrary removal."""
        raise TypeError("FrozenDict is immutable")

    @override
    def setdefault(self, *_args: object, **_kwargs: object) -> Never:
        """Reject insertion through defaulting."""
        raise TypeError("FrozenDict is immutable")

    @override
    def update(self, *_args: object, **_kwargs: object) -> Never:
        """Reject bulk mutation."""
        raise TypeError("FrozenDict is immutable")

    @override
    def __ior__(self, _value: object) -> Never:
        """Reject in-place merging."""
        raise TypeError("FrozenDict is immutable")


def deep_freeze(value: object) -> object:
    """Recursively convert mutable mappings and sequences to immutable values."""
    if isinstance(value, Mapping):
        mapping = cast("Mapping[object, object]", value)
        return FrozenDict({key: deep_freeze(item) for key, item in mapping.items()})
    if isinstance(value, (list, tuple)):
        sequence = cast("Iterable[object]", value)
        return tuple(deep_freeze(item) for item in sequence)
    if isinstance(value, (set, frozenset)):
        items = cast("Iterable[object]", value)
        return frozenset(deep_freeze(item) for item in items)
    return value
