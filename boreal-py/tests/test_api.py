import pytest
from .utils import MODULES


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_modules(module, is_yara):
    modules = module.modules

    assert type(modules) is list
    assert 'pe' in modules
    assert 'time' in modules
    assert 'console' in modules


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_version(module, is_yara):
    assert type(module.__version__) is str


# Test is marked as to be run last because it modifies a global config
# that impacts other tests.
@pytest.mark.parametrize('module,is_yara', MODULES)
def test_run_last_set_config_max_strings_per_rule(module, is_yara):
    module.set_config(max_strings_per_rule=2)

    if is_yara:
        exctype = module.SyntaxError
    else:
        exctype = module.AddRuleError
    with pytest.raises(exctype):
        module.compile(source="""
    rule a {
        strings:
            $a = "aaa"
            $b = "bbb"
            $c = "ccc"
        condition:
            any of them
    }
    """)


# Test is marked as to be run last because it modifies a global config
# that impacts other tests.
@pytest.mark.parametrize('module,is_yara', MODULES)
def test_run_last_set_config_max_match_data(module, is_yara):
    module.set_config(max_match_data=3)

    rules = module.compile(source="""
    rule a {
        strings:
            $a = "123456"
        condition:
            any of them
    }
    """)
    results = rules.match(data="<123456>")
    s = results[0].strings[0].instances[0]
    assert s.matched_data == b"123"
