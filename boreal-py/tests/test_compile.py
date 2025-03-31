import boreal
import pytest
import tempfile
import yara
from .utils import MODULES, MODULES_DISTINCT, YaraCompatibilityMode


@pytest.mark.parametrize('module', MODULES)
def test_compile_filepath(module):
    # Do not use NamedTemporaryFile, yara seems to get permission denied
    # issues on those type of files.
    with tempfile.TemporaryDirectory() as fd:
        path = f"{fd}/file"
        with open(path, "w") as f:
            f.write('rule a { condition: true }')

        # By default, it uses filepath
        rules = module.compile(path)
        matches = rules.match(data='')
        assert len(matches) == 1
        assert matches[0].rule == 'a'

        # Can also be specified
        rules = module.compile(filepath=path)
        matches = rules.match(data='')
        assert len(matches) == 1
        assert matches[0].rule == 'a'


@pytest.mark.parametrize('module', MODULES)
def test_compile_source(module):
    # Source specifies the string directly
    rules = module.compile(source='rule a { condition: true }')
    matches = rules.match(data='')
    assert len(matches) == 1
    assert matches[0].rule == 'a'


@pytest.mark.parametrize('module', MODULES)
def test_compile_file(module):
    with tempfile.TemporaryDirectory() as fd:
        path = f"{fd}/file"
        with open(path, "w") as f:
            f.write('rule a { condition: true }')

        with open(path, "r") as f:
            rules = module.compile(file=f)
        matches = rules.match(data='')
        assert len(matches) == 1
        assert matches[0].rule == 'a'


@pytest.mark.parametrize('module', MODULES)
def test_compile_filepaths(module):
    # filepaths allows specifying namespaces
    with tempfile.TemporaryDirectory() as fd:
        path1 = f"{fd}/file1"
        with open(path1, "w") as f:
            f.write('rule a { condition: true }')
        path2 = f"{fd}/file2"
        with open(path2, "w") as f:
            f.write('rule b { condition: true }')

        rules = module.compile(filepaths={
            'ns1': path1,
            'ns2': path2,
        })
        matches = rules.match(data='')
        assert len(matches) == 2
        assert matches[0].rule == 'a'
        assert matches[0].namespace ==  'ns1'
        assert matches[1].rule == 'b'
        assert matches[1].namespace == 'ns2'


@pytest.mark.parametrize('module', MODULES)
def test_compile_sources(module):
    # sources allows specifying namespaces
    rules = module.compile(sources={
        'ns1': 'rule a { condition: true }',
        'ns2': 'rule b { condition: true }',
    })
    matches = rules.match(data='')
    assert len(matches) == 2
    assert matches[0].rule == 'a'
    assert matches[0].namespace ==  'ns1'
    assert matches[1].rule == 'b'
    assert matches[1].namespace == 'ns2'


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
def test_compile_externals(module, is_yara):
    externals = {
        'b': True,
        's': 'foo',
        'i': -12,
        'f': 34.5,
    }
    rules = module.compile(externals=externals, source="""
rule a {
    condition:
        b and s == "foo" and i == -12 and f == 34.5
}""")
    matches = rules.match(data='')
    assert len(matches) == 1

    # boreal also accepts byte-string, while yara does not
    if is_yara:
        with pytest.raises(TypeError):
            module.compile(externals={ 's': b'foo' }, source="rule a { condition: true }")
    else:
        rules = module.compile(
            externals={ 's': b'f\xFFo' },
            source="""rule a { condition: s == "f\\xFFo" }"""
        )
        matches = rules.match(data='')
        assert len(matches) == 1


@pytest.mark.parametrize('module', MODULES)
def test_compile_includes(module):
    # By default, includes are allowed
    with tempfile.TemporaryDirectory() as fd:
        path = f"{fd}/file"
        with open(path, "w") as f:
            f.write('rule a { condition: true }')

        source = """
include "{path}"

rule b {{ condition: true }}
        """.format(path=path)
        rules = module.compile(source=source)
        matches = rules.match(data='')
        assert len(matches) == 2

        # But they can be disabled
        with pytest.raises(module.SyntaxError):
            module.compile(source=source, includes=False)


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
def test_compile_warnings(module, is_yara):
    # By default, warnings do not make the compilation fail
    source = """rule a { condition: "foo" }"""
    rules = module.compile(source=source)
    matches = rules.match(data="")
    assert len(matches) == 1

    # warnings can be found in the rules objects
    assert len(rules.warnings) == 1
    assert "boolean" in rules.warnings[0]

    # error_on_warning can modify this
    if is_yara:
        # Yara uses a different exception for warnings turned into errors.
        exctype = yara.WarningError
    else:
        exctype = boreal.AddRuleError
    with pytest.raises(exctype):
        module.compile(source=source, error_on_warning=True)


@pytest.mark.parametrize('module', MODULES)
def test_compile_warnings_contexts(module):
    # Test warnings are correctly handled in all the different contexts
    source1 = """rule a { condition: "foo" }"""
    source2 = """rule b { condition: "b" }"""

    rules = module.compile(source=source1 + source2)
    assert len(rules.warnings) == 2
    assert "boolean" in rules.warnings[0]
    assert "boolean" in rules.warnings[1]

    rules = module.compile(sources={ 'ns1': source1, 'ns2': source2 })
    assert len(rules.warnings) == 2
    assert "boolean" in rules.warnings[0]
    assert "boolean" in rules.warnings[1]

    with tempfile.TemporaryDirectory() as fd:
        path1 = f"{fd}/file1"
        with open(path1, "w") as f:
            f.write(source1)
        path2 = f"{fd}/file2"
        with open(path2, "w") as f:
            f.write(source2)

        rules = module.compile(filepath=path1)
        assert len(rules.warnings) == 1
        assert "boolean" in rules.warnings[0]

        with open(path1, "r") as f:
            rules = module.compile(file=f)
        assert len(rules.warnings) == 1
        assert "boolean" in rules.warnings[0]

        rules = module.compile(filepaths={ 'ns1': path1, 'ns2': path2 })
        assert len(rules.warnings) == 2
        assert "boolean" in rules.warnings[0]
        assert "boolean" in rules.warnings[1]


@pytest.mark.parametrize('module', MODULES)
def test_compile_errors_invalid_arguments(module):
    # Cannot specify multiple sources
    with pytest.raises(TypeError):
        module.compile(source="", sources={})
    with pytest.raises(TypeError):
        module.compile(filepath="", sources={})
    with pytest.raises(TypeError):
        module.compile(filepaths={}, sources={})
    with tempfile.TemporaryDirectory() as fd:
        path = f"{fd}/file"
        with open(path, "w") as f:
            f.write("rule")
        with open(path, "r") as f:
            with pytest.raises(TypeError):
                module.compile(file=f, sources={})
    with pytest.raises(TypeError):
        module.compile(source={}, filepaths={})

    with pytest.raises(TypeError):
        module.compile()


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
def test_compile_errors_invalid_types(module, is_yara):
    with pytest.raises(TypeError):
        module.compile(filepath=1)
    with pytest.raises(TypeError):
        module.compile(source=1)
    with pytest.raises(TypeError):
        module.compile(sources=1)
    with pytest.raises(TypeError):
        module.compile(filepaths=1)
    # segfaults in yara on Windows: https://github.com/VirusTotal/yara-python/pull/269
    if not is_yara:
        with pytest.raises(AttributeError):
            module.compile(file='str')

    with pytest.raises(TypeError):
        module.compile(sources={ 1: 'a' })
    with pytest.raises(TypeError):
        module.compile(sources={ 'a': 1 })

    with pytest.raises(TypeError):
        module.compile(filepaths={ 1: 'a' })
    with pytest.raises(TypeError):
        module.compile(filepaths={ 'a': 1 })

    source = 'rule a { condition: true }'
    # Broken in yara: https://github.com/VirusTotal/yara-python/pull/270
    if not is_yara:
        with pytest.raises(TypeError):
            module.compile(source=source, externals={ 1: 'a' })
    with pytest.raises(TypeError):
        module.compile(source=source, externals={ 'a': [1] })
    with pytest.raises(TypeError):
        module.compile(source=source, include_callback=1)
    with pytest.raises(TypeError):
        module.compile(source=source, strict_escape="a")


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
def test_compile_include_callback(module, is_yara):
    def include_cb(name, current, ns):
        if ns == "default":
            if name == "first":
                return """
                    include "../second"
                    rule b { condition: true }
                """
            elif name == "../second":
                return "rule c { condition: true }"
            else:
                return None
        elif ns == "ns":
            if name == "first":
                return """
                    include "../second"
                    rule d { condition: true }
                """
            elif name == "../second":
                return "rule e { condition: true }"
            else:
                return None
        else:
            return None

    data = """
        include "first"
        rule a { condition: true }
    """
    rules = module.compile(source=data, include_callback=include_cb)
    matches = rules.match(data="")
    assert sorted([r.rule for r in matches]) == ["a", "b", "c"]

    rules = module.compile(sources={ 'ns': data }, include_callback=include_cb)
    matches = rules.match(data="")
    assert sorted([r.rule for r in matches]) == ["a", "d", "e"]


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
def test_compile_include_callback_errors(module, is_yara):
    data = """
        include "first"
        rule a { condition: true }
    """

    # invalid return type
    def include_cb(name, current, ns):
        return 1
    with pytest.raises(module.SyntaxError):
        module.compile(source=data, include_callback=include_cb)

    # exception during call
    def include_cb(name, current, ns):
        raise Exception('dead')
    with pytest.raises(module.SyntaxError):
        module.compile(source=data, include_callback=include_cb)


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
def test_compile_strict_escape(module, is_yara):
    data = r"""
        rule a {
            strings:
                $a = /C:\Users/
            condition:
                $a
        }
    """

    with YaraCompatibilityMode():
        # By default, do not report unknown escape warnings
        rules = module.compile(source=data)
        assert len(rules.warnings) == 0

        # By default, do not report unknown escape warnings
        rules = module.compile(source=data, strict_escape=True)
        assert len(rules.warnings) == 1
        assert "unknown escape sequence" in rules.warnings[0]

        rules = module.compile(source=data, strict_escape=False)
        assert len(rules.warnings) == 0

    if not is_yara:
        # default behavior for boreal is enabling this warning
        rules = module.compile(source=data)
        assert len(rules.warnings) == 1
        assert "unknown escape sequence" in rules.warnings[0]

    # If disabling strict_escape but making warnings fails the
    # compilation, compilation should work
    rules = module.compile(source=data, strict_escape=False, error_on_warning=True)
    assert len(rules.warnings) == 0


def test_compiler_profile():
    # Yara does not have this, only test on boreal
    data = r"""
        rule a {
            strings:
                $a = "abc"
            condition:
                $a
        }
    """

    rules = boreal.compile(source=data, profile=boreal.CompilerProfile.Speed)
    matches = rules.match(data='abc')
    assert len(matches) == 1

    rules = boreal.compile(source=data, profile=boreal.CompilerProfile.Memory)
    matches = rules.match(data='abc')
    assert len(matches) == 1
