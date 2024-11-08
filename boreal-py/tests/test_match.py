import boreal
import pytest
import yara


MODULES = [
    (boreal, False),
    (yara, True),
]


RULE = """
rule foo: bar baz {
    meta:
        s = "a\\nz"
        b = true
        v = -11
    strings:
        $ = "fgj"
        $a = /l.{1,2}n/
    condition:
        any of them
}
"""

@pytest.mark.parametrize("module,is_yara", MODULES)
def test_match(module, is_yara):
    rule = module.compile(source=RULE)
    matches = rule.match(data='abcdefgjiklmnoprstuvwxyzlmmn')
    assert len(matches) == 1
    assert matches[0].rule == 'foo'
    # FIXME: difference between yara and boreal
    # assert matches[0].namespace == ''
    assert matches[0].tags == ['bar', 'baz']
    assert matches[0].meta == {
        # XXX yara forces a string type, losing information.
        's': 'a\nz' if is_yara else b'a\nz',
        'b': True,
        'v': -11
    }

    m = matches[0]
    assert len(m.strings) == 2
    assert m.strings[0].identifier == '$'
    assert len(m.strings[0].instances) == 1
    assert m.strings[0].instances[0].offset == 5
    assert m.strings[0].instances[0].matched_length == 3
    assert m.strings[0].instances[0].matched_data == b'fgj'

    assert m.strings[1].identifier == '$a'
    assert len(m.strings[1].instances) == 2
    assert m.strings[1].instances[0].offset == 10
    assert m.strings[1].instances[0].matched_length == 3
    assert m.strings[1].instances[0].matched_data == b'lmn'
    assert m.strings[1].instances[1].offset == 24
    assert m.strings[1].instances[1].matched_length == 4
    assert m.strings[1].instances[1].matched_data == b'lmmn'
