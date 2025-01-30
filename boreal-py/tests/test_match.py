import boreal
import glob
import platform
import os
import pytest
import subprocess
import tempfile
import yara


MODULES = [
    (boreal, False),
    (yara, True),
]


def get_rules(module):
    return module.compile(source="""
rule a {
    strings:
        $ = "abc"
        $ = /<\\d>/
    condition:
        all of them
}""")


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_filepath(module, is_yara):
    rules = get_rules(module)

    with tempfile.NamedTemporaryFile() as fp:
        fp.write(b'dcabc <3>')
        fp.flush()

        # By default, it uses filepath
        matches = rules.match(fp.name)
        assert len(matches) == 1

        # Can also be specified
        matches = rules.match(filepath=fp.name)
        assert len(matches) == 1


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_data(module, is_yara):
    rules = get_rules(module)

    matches = rules.match(data='dcabc <3>')
    assert len(matches) == 1


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_pid(module, is_yara):
    def discover_test_helper():
        # This is `<root>/boreal-py/tests`. We want to find `<root>/target/.../boreal-test-helpers(.exe)`.
        # We just do a glob to find it: we don't really care about the target or debug/release possibilities,
        # we just want a binary that runs.
        tests_dir = os.path.abspath(os.path.dirname(__file__))
        extension = '.exe' if platform.system() == 'Windows' else ''
        bin_name = f'boreal-test-helpers{extension}'
        bins = glob.glob(f"{tests_dir}/../../target/**/{bin_name}", recursive=True)
        if len(bins) == 0:
            raise Exception("you must compile the `boreal-test-helpers` crate to run this test")
        else:
            return bins[0]

    rules = module.compile(source="""
rule a {
    strings:
        $a = "PAYLOAD_ON_STACK"
    condition:
        all of them
}""")

    path_to_test_helper = discover_test_helper()
    child = subprocess.Popen([path_to_test_helper, "stack"], stdout=subprocess.PIPE)

    try:
        # Wait for the child to be ready
        while True:
            line = child.stdout.readline()
            if not line or line == b"ready\n":
                break

        matches = rules.match(pid=child.pid)
        assert len(matches) == 1
    finally:
        child.kill()
        child.wait()


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_externals(module, is_yara):
    rules = module.compile(source="""
rule a {
    condition:
        s == "foo" and b and i == -12 and f == 35.2
}""", externals={
        's': '',
        'b': False,
        'i': 0,
        'f': 1.1,
    })

    matches = rules.match(data='')
    assert len(matches) == 0

    matches = rules.match(data='', externals={
        's': 'foo',
        'b': True,
        'i': -12,
        'f': 35.2,
    })
    assert len(matches) == 1

    matches = rules.match(data='')
    assert len(matches) == 0

    matches = rules.match(data='', externals={
        's': 'foo',
        'b': True,
        'i': -13,
        'f': 35.2,
    })
    assert len(matches) == 0


def test_match_externals_bytestring():
    # Boreal supports byte strings as externals, but not yara
    rules = boreal.compile(source="""
rule a {
    condition:
        bs == "x\\xFFy"
}""", externals={
        'bs': '',
    })

    matches = rules.match(data='')
    assert len(matches) == 0

    matches = rules.match(data='', externals={
        'bs': b'x\xFFy',
    })
    assert len(matches) == 1

    matches = rules.match(data='')
    assert len(matches) == 0

    matches = rules.match(data='', externals={
        'bs': b'x\xFFb',
    })
    assert len(matches) == 0


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_invalid_types(module, is_yara):
    rules = get_rules(module)

    with pytest.raises(TypeError):
        rules.match(filepath=1)
    with pytest.raises(TypeError):
        rules.match(data=1)
    with pytest.raises(TypeError):
        rules.match(pid='a')
    with pytest.raises(TypeError):
        rules.match()

    # FIXME: this makes yara segfault...
    if not is_yara:
        with pytest.raises(TypeError):
            rules.match(data='', externals={ 1: 'a' })

    with pytest.raises(TypeError):
        rules.match(data='', externals={ 'a': [1] })


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_externals_unknown(module, is_yara):
    rules = get_rules(module)

    # Specifying externals not specified during compilation is not an error
    # and is ignored.
    matches = rules.match(data='dcabc <5>', externals={ 'b': 1 })
    assert len(matches) == 1


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_scan_failed(module, is_yara):
    rules = get_rules(module)

    if is_yara:
        exctype = yara.Error
    else:
        exctype = boreal.ScanError

    with pytest.raises(exctype):
        rules.match(pid=99999999)


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_timeout(module, is_yara):
    rules = module.compile(source="""
rule a {
    condition:
        for all i in (0..9223372036854775807) : (
            for all j in (0..9223372036854775807) : (
                for all k in (0..9223372036854775807) : (
                    for all l in (0..9223372036854775807) : (
                        i + j + k + l >= 0
                    )
                )
            )
        )
}""")

    if is_yara:
        exctype = yara.TimeoutError
    else:
        exctype = boreal.TimeoutError

    with pytest.raises(exctype):
        # Unfortunately, we cannot go below 1 second as this is the smallest timeout value
        # in the yara api
        rules.match(data='', timeout=1)
