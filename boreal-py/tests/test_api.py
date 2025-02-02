import pytest
from .utils import MODULES


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_modules(module, is_yara):
    modules = module.modules

    assert type(modules) is list
    assert 'pe' in modules
    assert 'time' in modules
    assert 'console' in modules
