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


@pytest.mark.parametrize("module,is_yara", MODULES)
def test_string_match(module, is_yara):
    """Test all properties related to the StringMatch object"""
    rule = module.compile(source="""
rule foo {
    strings:
        $ = /<.{1,3}>/
    condition:
        any of them
}""")
    matches = rule.match(data=b'<a> <\td> <\x00\xFF\xFB> <a>')
    assert len(matches) == 1
    m = matches[0]
    assert len(m.strings) == 1
    s = m.strings[0]
    assert len(s.instances) == 4
    i0 = s.instances[0]
    i1 = s.instances[1]
    i2 = s.instances[2]
    i3 = s.instances[3]

    # check standard getters: offset, matched_data, matched_length
    assert i0.offset == 0
    assert i0.matched_length == 3
    assert i0.matched_data == b'<a>'
    assert i1.offset == 4
    assert i1.matched_length == 4
    assert i1.matched_data == b'<\td>'
    assert i2.offset == 9
    assert i2.matched_length == 5
    assert i2.matched_data == b'<\x00\xFF\xFB>'

    # TODO: missing xor_key and plaintext

    # check special method __repr__
    assert i0.__repr__() == '<a>'
    assert i1.__repr__() == '<\td>'
    # TODO: difference here, should we care about it?
    assert i2.__repr__() == '<\x00\\xff\\xfb>' if is_yara else '<\x00\uFFFD\uFFFD>'

    # Check that the hash depends only on the matched_data
    assert hash(i0) == hash(i3)
