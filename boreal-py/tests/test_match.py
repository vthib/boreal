import boreal
import pytest
import yara


MODULES = [
    boreal,
    yara
]


@pytest.mark.parametrize("module", MODULES)
def test_match(module):
    rule = module.compile(source='rule foo: bar {strings: $a = "lmn" condition: $a}')
    matches = rule.match(data='abcdefgjiklmnoprstuvwxyz')
    assert len(matches) == 1
    assert matches[0].rule == 'foo'
    assert matches[0].tags == ['bar']
    assert len(matches[0].strings) == 1
    # TODO: difference with yara
    assert matches[0].strings[0].identifier == '$a'
    assert len(matches[0].strings[0].instances) == 1
    assert matches[0].strings[0].instances[0].offset == 10
    assert matches[0].strings[0].instances[0].matched_length == 3
    assert matches[0].strings[0].instances[0].matched_data == b'lmn'
