import pytest
from .utils import MODULES


@pytest.mark.parametrize('module', MODULES)
def test_modules(module):
    modules = module.modules

    assert type(modules) is list
    assert 'pe' in modules
    assert 'time' in modules
    assert 'console' in modules


@pytest.mark.parametrize('module', MODULES)
def test_version(module):
    assert type(module.__version__) is str


# Test is marked as to be run last because it modifies a global config
# that impacts other tests.
@pytest.mark.parametrize('module', MODULES)
def test_run_last_set_config_max_strings_per_rule(module):
    module.set_config(max_strings_per_rule=2)

    with pytest.raises(module.SyntaxError):
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
@pytest.mark.parametrize('module', MODULES)
def test_run_last_set_config_max_match_data(module):
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


@pytest.mark.parametrize('module', MODULES)
def test_run_last_set_config_stack_size(module):
    # Just check isetting stack_size doesn't fail
    module.set_config(stack_size=10_000)
