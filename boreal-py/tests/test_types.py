import pytest
from .utils import MODULES, MODULES_DISTINCT, YaraCompatibilityMode


@pytest.mark.parametrize("module", MODULES)
def test_match(module):
    """Test all properties related to the Match object"""

    # Check default namespace
    rule = module.compile(source="rule a { condition: true }")
    matches = rule.match(data='')
    assert len(matches) == 1
    assert matches[0].namespace == 'default'

    # Check with multiple namespaces
    source = """
rule r1: bar baz {
    meta:
        s = "a\\nz"
        b = true
        v = -11
    condition:
        true
}

rule r2: quux { condition: false }
rule r3 { condition: true }
"""

    rules = module.compile(sources={
        'ns1': source,
        'ns2': source,
    })
    rules2 = module.compile(sources={
        'ns1': 'rule r1 { condition: true }',
        'ns2': 'rule r1 { condition: true }',
    })
    # Enable compatibility mode to get a string in the meta object instead of
    # a byte string, see the test_meta_bytes test.
    with YaraCompatibilityMode():
        matches = rules.match(data='')
    assert len(matches) == 4
    m0 = matches[0]
    m1 = matches[1]
    m2 = matches[2]
    m3 = matches[3]

    matches2 = rules2.match(data='')
    assert len(matches2) == 2
    r2_m0 = matches2[0]
    r2_m1 = matches2[1]

    assert m0.rule == 'r1'
    assert m0.namespace == 'ns1'
    assert m0.tags == ['bar', 'baz']
    assert m0.meta == {
        's': 'a\nz',
        'b': True,
        'v': -11
    }

    assert m1.rule == 'r3'
    assert m1.namespace == 'ns1'

    assert m2.rule == 'r1'
    assert m2.namespace == 'ns2'

    assert m3.rule == 'r3'
    assert m3.namespace == 'ns2'

    # check special method __repr__
    assert m0.__repr__() == 'r1'
    assert m1.__repr__() == 'r3'
    assert m2.__repr__() == 'r1'
    assert m3.__repr__() == 'r3'
    assert r2_m0.__repr__() == 'r1'
    assert r2_m1.__repr__() == 'r1'

    assert hash(m0) != hash(m1) # rule name differs
    assert hash(m0) != hash(m2) # namespace name differs
    assert hash(m0) == hash(r2_m0) # same name and namespace
    assert hash(m0) != hash(r2_m1)

    # check richcmp impl
    # eq
    assert not (m0 == m1)
    assert not (m0 == m2)
    assert m0 == r2_m0
    # ne
    assert (m0 != m1)
    assert (m0 != m2)
    assert not (m0 != r2_m0)
    # <=
    assert m0 <= m1
    assert not (m1 <= m2)
    assert m0 <= m2
    assert m0 <= r2_m0
    # <
    assert m0 < m1
    assert not (m1 < m2)
    assert m0 < m2
    assert not (m0 < r2_m0)
    # >=
    assert m1 >= m0
    assert not (m2 >= m1)
    assert m2 >= m0
    assert r2_m0 >= m0
    # >
    assert m1 > m0
    assert not (m2 > m1)
    assert m2 > m0
    assert not (r2_m0 > m0)


@pytest.mark.parametrize("module,is_yara", MODULES_DISTINCT)
def test_string_matches(module, is_yara):
    """Test all properties related to the StringMatches object"""
    rule = module.compile(source="""
rule foo {
    strings:
        $ = "a"
        $ = "b"
        $c = "c"
    condition:
        any of them
}""")
    # Compat mode to get the identifiers with the '$' prefix
    with YaraCompatibilityMode():
        matches = rule.match(data=b'abca')

    assert len(matches) == 1
    m = matches[0]
    assert len(m.strings) == 3
    s0 = m.strings[0]
    s1 = m.strings[1]
    s2 = m.strings[2]

    # check standard getters: identifier, instances
    assert s0.identifier == '$'
    assert len(s0.instances) == 2
    assert s1.identifier == '$'
    assert len(s1.instances) == 1
    assert s2.identifier == '$c'
    assert len(s2.instances) == 1

    # check special method __repr__
    assert s0.__repr__() == '$'
    assert s1.__repr__() == '$'
    assert s2.__repr__() == '$c'

    # In yara, the hash depends on the name only
    with YaraCompatibilityMode():
        assert hash(s0) == hash(s1)
    # outside of compat mode, this is not true
    if not is_yara:
        assert hash(s0) != hash(s1)

    # Outside compat mode, we do not have this '$' prefix
    if not is_yara:
        matches = rule.match(data=b'abca')
        m = matches[0]
        s0 = m.strings[0]
        s1 = m.strings[1]
        s2 = m.strings[2]

        assert s0.identifier == ''
        assert s1.identifier == ''
        assert s2.identifier == 'c'


@pytest.mark.parametrize("module,is_yara", MODULES_DISTINCT)
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

    # check special method __repr__
    assert i0.__repr__() == '<a>'
    assert i1.__repr__() == '<\td>'
    # XXX: difference here, but i don't think this is a big deal.
    assert i2.__repr__() == '<\x00\\xff\\xfb>' if is_yara else '<\x00\uFFFD\uFFFD>'

    # In yara, the hash depends only on the matched_data
    with YaraCompatibilityMode():
        assert hash(i0) == hash(i3)
    # outside of compat mode, this is not true
    if not is_yara:
        assert hash(i0) != hash(i3)


@pytest.mark.parametrize("module", MODULES)
def test_string_match_instance_xor_key(module):
    rule = module.compile(source="""
rule my_rule {
    strings:
        $a = "aaa" ascii wide xor
        $b = "ccc"
    condition:
        any of them
}""")
    matches = rule.match(data=b'abcccba B#B#B#')
    assert len(matches) == 1
    m = matches[0]
    assert len(m.strings) == 2
    s0 = m.strings[0]
    s1 = m.strings[1]
    assert s0.is_xor()
    assert not s1.is_xor()

    assert len(s0.instances) == 2
    i0 = s0.instances[0]
    i1 = s0.instances[1]

    assert i0.xor_key == 0x02
    assert i0.matched_data == b"ccc"
    assert i0.plaintext() == b"aaa"
    assert i1.xor_key == 0x23
    assert i1.matched_data == b"B#B#B#"
    assert i1.plaintext() == b"a\0a\0a\0"

    assert len(s1.instances) == 1
    i1 = s1.instances[0]
    assert i1.xor_key == 0
    assert i1.matched_data == b"ccc"
    assert i1.plaintext() == b"ccc"


@pytest.mark.parametrize("module,is_yara", MODULES_DISTINCT)
def test_meta_bytes(module, is_yara):
    rules = module.compile(source="""
rule a {
    meta:
        s = "b\\xFFc"
    condition: true
}""")
    # By default, boreal returns a proper byte string
    if not is_yara:
        matches = rules.match(data='')
        assert matches[0].meta['s'] == b'b\xFFc'

    # In compat mode, the same string conversion as done in libyara
    # is done.
    with YaraCompatibilityMode():
        matches = rules.match(data='')
        assert matches[0].meta['s'] == 'bc'

    # Same is true when iterating on rules
    if not is_yara:
        r = list(rules)[0]
        assert r.meta['s'] == b'b\xFFc'
    with YaraCompatibilityMode():
        r = list(rules)[0]
        assert r.meta['s'] == 'bc'
