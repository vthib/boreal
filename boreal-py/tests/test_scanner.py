import boreal
import glob
import platform
import os
import pytest
import subprocess
import tempfile
import yara
from .utils import MODULES


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

    with pytest.raises(TypeError):
        rules.match(data='', console_callback=1)
    with pytest.raises(TypeError):
        rules.match(data='', callback=1)
    with pytest.raises(TypeError):
        rules.match(data='', modules_callback=1)
    with pytest.raises(TypeError):
        rules.match(data='', which_callbacks="str")


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


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_console_log(module, is_yara, capsys):
    rules = module.compile(source="""
import "console"

rule a {
    condition:
        console.log("i am a log") and true
}""")

    rules.match(data='')
    captured = capsys.readouterr()
    assert captured.out == "i am a log\n"
    assert captured.err == ""

    # Can override the callback
    rules.match(data='', console_callback=lambda log: print(f"override <{log}>"))
    captured = capsys.readouterr()
    assert captured.out == "override <i am a log>\n"
    assert captured.err == ""


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_modules_data(module, is_yara):
    # Test only works if the cuckoo module is present
    if 'cuckoo' not in module.modules:
        return

    rules = boreal.compile(source="""
import "cuckoo"

rule a {
    condition:
        cuckoo.network.host(/bcd/) == 1
}""")

    matches = rules.match(data='', modules_data={
        'cuckoo': '{ "network": { "hosts": ["abcde"] } }'
    })
    assert len(matches) == 1


def test_match_modules_data_errors():
    rules = get_rules(boreal)

    # YARA does not reject this, as the list is not checked.
    with pytest.raises(TypeError):
        rules.match(data="", modules_data={ 'unknown': 1 })

    if 'cuckoo' in boreal.modules:
        with pytest.raises(TypeError):
            rules.match(data="", modules_data={ 'cuckoo': 1 })
        with pytest.raises(TypeError):
            rules.match(data="", modules_data={ 'cuckoo': "invalid json" })


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_rules(module, is_yara):
    scanner = module.compile(sources={
        'ns1': """
global rule g {
    condition: true
}
private rule p: tag {
    meta:
        b = true
    condition: true
}
""",
        'ns2': """
private global rule pg: tag1 tag2 {
    meta:
        s = "str"
        i = -23
    condition: true
}

rule r: tag {
    condition: true
}
"""
    })

    rules = [r for r in scanner]
    # boreal and yara do not return rules in the same order
    rules.sort(key=lambda r: r.identifier)
    assert len(rules) == 4
    r0 = rules[0]
    r1 = rules[1]
    r2 = rules[2]
    r3 = rules[3]

    assert r0.identifier == "g"
    # boreal also provides the namespace
    if not is_yara:
        assert r0.namespace == "ns1"
    assert r0.tags == []
    assert r0.is_global
    assert not r0.is_private
    assert r0.meta == {}

    assert r1.identifier == "p"
    if not is_yara:
        assert r1.namespace == "ns1"
    assert r1.tags == ["tag"]
    assert not r1.is_global
    assert r1.is_private
    assert r1.meta == {
        'b': True
    }

    assert r2.identifier == "pg"
    if not is_yara:
        assert r2.namespace == "ns2"
    assert r2.tags == ["tag1", "tag2"]
    assert r2.is_global
    assert r2.is_private
    assert r2.meta == {
        # XXX yara forces a string type, losing information.
        's': 'str' if is_yara else b'str',
        'i': -23
    }

    assert r3.identifier == "r"
    if not is_yara:
        assert r3.namespace == "ns2"
    assert r3.tags == ["tag"]
    assert not r3.is_global
    assert not r3.is_private
    assert r3.meta == {}

    # Test the namespace value for the default one
    if not is_yara:
        scanner = module.compile(source="rule a { condition: true }")
        rules = [r for r in scanner]
        assert rules[0].namespace == ""


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_callback(module, is_yara):
    rules = module.compile(source="""
global rule a: tag1 tag2 {
    meta:
        s = "str"
        i = -23
    strings:
        $a = "abc"
        $ = /<\\d>/
    condition:
        any of them
}
rule b { condition: false }
""")

    callback_rules = []
    def my_callback(rule):
        nonlocal callback_rules
        callback_rules.append(rule)
        return module.CALLBACK_CONTINUE

    matches = rules.match(
        data='dcabc <3>',
        which_callbacks=yara.CALLBACK_MATCHES,
        callback=my_callback
    )
    assert len(matches) == 1
    assert len(callback_rules) == 1

    def check_strings(strings):
        assert len(strings) == 2
        s0 = strings[0]
        assert s0.identifier == "$a"
        assert len(s0.instances) == 1
        assert s0.instances[0].offset == 2
        assert s0.instances[0].matched_length == 3
        assert s0.instances[0].matched_data == b'abc'

        s1 = strings[1]
        assert s1.identifier == "$"
        assert len(s1.instances) == 1
        assert s1.instances[0].offset == 6
        assert s1.instances[0].matched_length == 3
        assert s1.instances[0].matched_data == b'<3>'

    r = matches[0]
    assert r.rule == "a"
    assert r.namespace == ("default" if is_yara else "")
    assert r.tags == ["tag1", "tag2"]
    assert r.meta == {
        's': 'str' if is_yara else b'str',
        'i': -23,
    }
    check_strings(r.strings)

    r = callback_rules[0]
    assert r['matches']
    assert r['rule'] == "a"
    assert r['namespace'] == ("default" if is_yara else "")
    assert r['tags'] == ["tag1", "tag2"]
    assert r['meta'] == {
        's': 'str' if is_yara else b'str',
        'i': -23,
    }
    check_strings(r['strings'])


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_callback_return_value(module, is_yara):
    rules = module.compile(source="""
rule a { condition: true }
rule b { condition: true }
rule c { condition: true }
""")

    # Not returning anything is OK
    callback_rules = []
    def cb_no_return(rule):
        nonlocal callback_rules
        callback_rules.append(rule)
    matches = rules.match(data='', which_callbacks=module.CALLBACK_MATCHES, callback=cb_no_return)
    assert ['a', 'b', 'c'] == [r.rule for r in matches]
    assert ['a', 'b', 'c'] == [r['rule'] for r in callback_rules]

    # Returning a non long value is OK as well
    callback_rules = []
    def cb_bad_return(rule):
        nonlocal callback_rules
        callback_rules.append(rule)
        return "str"
    matches = rules.match(data='', which_callbacks=module.CALLBACK_MATCHES, callback=cb_bad_return)
    assert ['a', 'b', 'c'] == [r.rule for r in matches]
    assert ['a', 'b', 'c'] == [r['rule'] for r in callback_rules]

    # Abort at some point
    callback_rules = []
    def cb_abort(rule):
        nonlocal callback_rules
        callback_rules.append(rule)
        if rule['rule'] == 'b':
            return module.CALLBACK_ABORT
    matches = rules.match(data='', which_callbacks=module.CALLBACK_MATCHES, callback=cb_abort)
    assert ['a', 'b'] == [r.rule for r in matches]
    assert ['a', 'b'] == [r['rule'] for r in callback_rules]

    # Throw inside the callback
    callback_rules = []
    def cb_throw(rule):
        nonlocal callback_rules
        callback_rules.append(rule)
        if rule['rule'] == 'b':
            raise Exception('dead')
    with pytest.raises(Exception):
        matches = rules.match(data='', which_callbacks=module.CALLBACK_MATCHES, callback=cb_throw)
    assert ['a', 'b'] == [r.rule for r in matches]
    assert ['a', 'b'] == [r['rule'] for r in callback_rules]


def test_match_which_callbacks():
    rules = boreal.compile(source="rule a { condition: true }")

    def my_callback(_):
        return boreal.CALLBACK_CONTINUE

    # Anything other than CALLBACK_MATCHES is not supported
    with pytest.raises(ValueError):
        rules.match(data='', callback=my_callback)
    with pytest.raises(ValueError):
        rules.match(data='', callback=my_callback, which_callbacks=boreal.CALLBACK_NON_MATCHES)
    with pytest.raises(ValueError):
        rules.match(data='', callback=my_callback, which_callbacks=boreal.CALLBACK_ALL)


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_modules_callback(module, is_yara):
    rules = module.compile(source="""
import "pe"

rule a { condition: true }
""")

    received_values = []
    def modules_callback(v):
        nonlocal received_values
        received_values.append(v)
        return boreal.CALLBACK_CONTINUE

    rules.match('../boreal/tests/assets/libyara/data/mtxex.dll', modules_callback=modules_callback)

    assert len(received_values) == 1
    v = received_values[0]
    # string
    assert v['module'] == 'pe'
    # integer
    assert v['base_of_code'] == 4096
    # missing value
    assert 'base_of_data' not in v
    # array
    assert v['resources'] == [{
        'id': 1,
        'language': 1033,
        'length': 888,
        'offset': 8288,
        'rva': 20576,
        'type': 16,
    }]
    # empty array
    assert v['delayed_import_details'] == []
    # obj
    assert v['os_version'] == { 'major': 10, 'minor': 0 }
    # dict
    assert v['version_info']['InternalName'] == b'MTXEX.DLL'
    # non printable bytes
    assert v['version_info']['ProductName'] == b'Microsoft\xAE Windows\xAE Operating System'


@pytest.mark.parametrize('module,is_yara', MODULES)
def test_match_modules_callback_abort(module, is_yara):
    rules = module.compile(source="""
import "math"
import "time"

rule a { condition: true }
""")

    received_values = []
    def modules_callback(v):
        nonlocal received_values
        received_values.append(v)
        return boreal.CALLBACK_ABORT

    rules.match(data='', modules_callback=modules_callback)

    # FIXME: difference with yara here
    if is_yara:
        assert len(received_values) == 2
        assert received_values[0]['module'] == 'math'
        assert received_values[1]['module'] == 'time'
    else:
        assert len(received_values) == 1
        assert received_values[0]['module'] == 'math'
