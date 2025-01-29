import boreal
import pytest
import tempfile
import yara


MODULES = [
    (boreal, False),
    (yara, True),
]


def compile_exc_type(is_yara):
    if is_yara:
        return yara.SyntaxError
    else:
        return boreal.AddRuleError


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_compile_filepath(module, is_yara):
    with tempfile.NamedTemporaryFile() as fp:
        fp.write(b'rule a { condition: true }')
        fp.flush()

        # By default, it uses filepath
        rules = module.compile(fp.name)
        matches = rules.match(data='')
        assert len(matches) == 1
        assert matches[0].rule == 'a'

        # Can also be specified
        rules = module.compile(filepath=fp.name)
        matches = rules.match(data='')
        assert len(matches) == 1
        assert matches[0].rule == 'a'


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_compile_source(module, is_yara):
    # Source specifies the string directly
    rules = module.compile(source='rule a { condition: true }')
    matches = rules.match(data='')
    assert len(matches) == 1
    assert matches[0].rule == 'a'


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_compile_file(module, is_yara):
    with tempfile.TemporaryFile() as fp:
        fp.write(b'rule a { condition: true }')
        fp.flush()
        fp.seek(0)

        rules = module.compile(file=fp)
        matches = rules.match(data='')
        assert len(matches) == 1
        assert matches[0].rule == 'a'


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_compile_filepaths(module, is_yara):
    # filepaths allows specifying namespaces
    with tempfile.NamedTemporaryFile() as fp1, tempfile.NamedTemporaryFile() as fp2:
        fp1.write(b'rule a { condition: true }')
        fp1.flush()
        fp2.write(b'rule b { condition: true }')
        fp2.flush()

        rules = module.compile(filepaths={
            'ns1': fp1.name,
            'ns2': fp2.name
        })
        matches = rules.match(data='')
        assert len(matches) == 2
        assert matches[0].rule == 'a'
        assert matches[0].namespace ==  'ns1'
        assert matches[1].rule == 'b'
        assert matches[1].namespace == 'ns2'


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_compile_sources(module, is_yara):
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


@pytest.mark.parametrize('module,is_yara', MODULES)
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


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_compile_includes(module, is_yara):
    # By default, includes are allowed
    with tempfile.NamedTemporaryFile() as fp1:
        fp1.write(b"rule a { condition: true }")
        fp1.flush()

        source = """
include "{path}"

rule b {{ condition: true }}
        """.format(path=fp1.name)
        rules = module.compile(source=source)
        matches = rules.match(data='')
        assert len(matches) == 2

        # But they can be disabled
        exctype = compile_exc_type(is_yara)
        with pytest.raises(exctype):
            module.compile(source=source, includes=False)


@pytest.mark.parametrize('module,is_yara', MODULES)
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


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_compile_warnings_contexts(module, is_yara):
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

    with tempfile.NamedTemporaryFile() as fp1, tempfile.NamedTemporaryFile() as fp2:
        fp1.write(source1.encode())
        fp1.flush()
        fp1.seek(0)
        fp2.write(source2.encode())
        fp2.flush()
        fp2.seek(0)

        rules = module.compile(filepath=fp1.name)
        assert len(rules.warnings) == 1
        assert "boolean" in rules.warnings[0]

        rules = module.compile(file=fp1)
        assert len(rules.warnings) == 1
        assert "boolean" in rules.warnings[0]

        rules = module.compile(filepaths={ 'ns1': fp1.name, 'ns2': fp2.name })
        assert len(rules.warnings) == 2
        assert "boolean" in rules.warnings[0]
        assert "boolean" in rules.warnings[1]


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_compile_errors_invalid_arguments(module, is_yara):
    # Cannot specify multiple sources
    with pytest.raises(TypeError):
        module.compile(source="", sources={})
    with pytest.raises(TypeError):
        module.compile(filepath="", sources={})
    with pytest.raises(TypeError):
        module.compile(filepaths={}, sources={})
    with tempfile.NamedTemporaryFile() as fp:
        with pytest.raises(TypeError):
            module.compile(file=fp, sources={})
    with pytest.raises(TypeError):
        module.compile(source={}, filepaths={})

    with pytest.raises(TypeError):
        module.compile()


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_compile_errors_invalid_types(module, is_yara):
    with pytest.raises(TypeError):
        module.compile(filepath=1)
    with pytest.raises(TypeError):
        module.compile(source=1)
    with pytest.raises(TypeError):
        module.compile(sources=1)
    with pytest.raises(TypeError):
        module.compile(filepaths=1)
    # FIXME: yara segfaults on this on Windows
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
    # FIXME: difference here between boreal and yara
    # with pytest.raises(TypeError):
    #     module.compile(source=source, externals={ 1: 'a' })
    with pytest.raises(TypeError):
        module.compile(source=source, externals={ 'a': [1] })


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_compile_errors_compilation(module, is_yara):
    exctype = compile_exc_type(is_yara)

    with tempfile.NamedTemporaryFile() as fp:
        fp.write(b'rule')
        fp.flush()
        fp.seek(0)

        with pytest.raises(exctype):
            module.compile(filepath=fp.name)
        with pytest.raises(exctype):
            module.compile(filepaths={ 'ns': fp.name })
        with pytest.raises(exctype):
            module.compile(file=fp)

    with pytest.raises(exctype):
        module.compile(source='rule')
    with pytest.raises(exctype):
        module.compile(sources={ 'ns': 'rule' })
