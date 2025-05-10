import boreal
import glob
import platform
import os
import pytest
import subprocess
import tempfile
import yara
from .utils import MODULES, MODULES_DISTINCT, YaraCompatibilityMode


def get_rules(module):
    return module.compile(source="""
rule a {
    strings:
        $ = "abc"
        $ = /<\\d>/
    condition:
        all of them
}""")


@pytest.mark.parametrize('module', MODULES)
def test_match_filepath(module):
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


@pytest.mark.parametrize('module', MODULES)
def test_match_data(module):
    rules = get_rules(module)

    matches = rules.match(data='dcabc <3>')
    assert len(matches) == 1


@pytest.mark.parametrize('module', MODULES)
def test_match_pid(module):
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


@pytest.mark.parametrize('module', MODULES)
def test_match_externals(module):
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


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
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

    # Broken in yara: https://github.com/VirusTotal/yara-python/pull/270
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
        rules.match(data='', warnings_callback=1)
    with pytest.raises(TypeError):
        rules.match(data='', which_callbacks="str")


@pytest.mark.parametrize('module', MODULES)
def test_match_externals_unknown(module):
    rules = get_rules(module)

    # Specifying externals not specified during compilation is not an error
    # and is ignored.
    matches = rules.match(data='dcabc <5>', externals={ 'b': 1 })
    assert len(matches) == 1


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
def test_match_scan_failed(module, is_yara):
    rules = get_rules(module)

    if is_yara:
        exctype = yara.Error
    else:
        exctype = boreal.ScanError

    with pytest.raises(exctype):
        rules.match(pid=99999999)


@pytest.mark.parametrize('module', MODULES)
def test_match_timeout(module):
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

    with pytest.raises(module.TimeoutError):
        # Unfortunately, we cannot go below 1 second as this is the smallest timeout value
        # in the yara api
        rules.match(data='', timeout=1)


@pytest.mark.parametrize('module', MODULES)
def test_match_console_log(module, capsys):
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


@pytest.mark.parametrize('module', MODULES)
def test_match_modules_data(module):
    # Test only works if the cuckoo module is present
    if 'cuckoo' not in module.modules:
        return

    rules = module.compile(source="""
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


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
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

    if not is_yara:
        # Test the namespace value for the default one
        scanner = module.compile(source="rule a { condition: true }")
        rules = [r for r in scanner]
        assert rules[0].namespace == "default"


@pytest.mark.parametrize('module', MODULES)
def test_match_callback(module):
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

    # Compat mode to get the '$' prefix for identifiers
    with YaraCompatibilityMode():
        matches = rules.match(
            data='dcabc <3>',
            which_callbacks=module.CALLBACK_MATCHES,
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
    assert r.namespace == "default"
    assert r.tags == ["tag1", "tag2"]
    assert r.meta == {
        's': 'str',
        'i': -23,
    }
    check_strings(r.strings)

    r = callback_rules[0]
    assert r['matches']
    assert r['rule'] == "a"
    assert r['namespace'] == "default"
    assert r['tags'] == ["tag1", "tag2"]
    assert r['meta'] == {
        's': 'str',
        'i': -23,
    }
    check_strings(r['strings'])


@pytest.mark.parametrize('module', MODULES)
def test_match_callback_return_value(module):
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


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
def test_match_modules_callback(module, is_yara):
    rules = module.compile(source="""
import "pe"

rule a { condition: true }
""")

    received_values = []
    def modules_callback(v):
        nonlocal received_values
        received_values.append(v)
        return module.CALLBACK_CONTINUE

    with YaraCompatibilityMode():
        rules.match('../boreal/tests/assets/libyara/data/mtxex.dll', modules_callback=modules_callback)

    assert len(received_values) == 1
    v = received_values[0]

    # static values are present
    assert v['DLL'] == 8192
    # but functions are not included
    assert 'section_index' not in v

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

    # Without compat mode, the keys of dictionary values are byte strings.
    if not is_yara:
        received_values = []
        rules.match('../boreal/tests/assets/libyara/data/mtxex.dll', modules_callback=modules_callback)

        assert len(received_values) == 1
        v = received_values[0]
        assert v['version_info'][b'InternalName'] == b'MTXEX.DLL'
        assert v['version_info'][b'ProductName'] == b'Microsoft\xAE Windows\xAE Operating System'



@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
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
        return module.CALLBACK_ABORT

    rules.match(data='', modules_callback=modules_callback)

    # Difference with yara here, but it's not a big deal.
    if is_yara:
        assert len(received_values) == 2
        assert received_values[0]['module'] == 'math'
        assert received_values[1]['module'] == 'time'
    else:
        assert len(received_values) == 1
        assert received_values[0]['module'] == 'math'


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
def test_match_which_callbacks(module, is_yara):
    rules = module.compile(source="""
rule a { condition: true }
rule b { condition: false }
""")

    received_values = []
    def callback(v):
        nonlocal received_values
        received_values.append(v)
        return module.CALLBACK_CONTINUE

    def check_all(received_values, matches):
        assert len(received_values) == 2
        assert received_values[0]['rule'] == 'a'
        assert received_values[0]['matches']
        assert received_values[1]['rule'] == 'b'
        assert not received_values[1]['matches']
        assert len(matches) == 1
        assert matches[0].rule == 'a'

    def check_only_matching(received_values, matches):
        assert len(received_values) == 1
        assert received_values[0]['rule'] == 'a'
        assert received_values[0]['matches']
        assert len(matches) == 1
        assert matches[0].rule == 'a'

    # check CALLBACK_ALL
    matches = rules.match(data='', which_callbacks=module.CALLBACK_ALL, callback=callback)
    check_all(received_values, matches)

    # In compatibility mode, not specifying defaults to ALL
    with YaraCompatibilityMode():
        received_values = []
        matches = rules.match(data='', callback=callback)
        check_all(received_values, matches)

    # Outside of it, it defaults to MATCHES
    if not is_yara:
        received_values = []
        matches = rules.match(data='', callback=callback)
        check_only_matching(received_values, matches)

    # only match
    received_values = []
    matches = rules.match(data='', which_callbacks=module.CALLBACK_MATCHES, callback=callback)
    check_only_matching(received_values, matches)

    # only non match
    received_values = []
    matches = rules.match(data='', which_callbacks=module.CALLBACK_NON_MATCHES, callback=callback)
    assert len(received_values) == 1
    assert received_values[0]['rule'] == 'b'
    assert not received_values[0]['matches']
    # Returned results still include the matched rules
    assert len(matches) == 1
    assert matches[0].rule == 'a'


@pytest.mark.parametrize('module', MODULES)
def test_match_which_all_abort(module):
    rules = module.compile(source="""
rule a { condition: true }
rule b { condition: false }
rule c { condition: true }
rule d { condition: false }
""")

    received_values = []
    def callback(abort_name, v):
        nonlocal received_values
        received_values.append(v)
        if v['rule'] == abort_name:
            return module.CALLBACK_ABORT
        return module.CALLBACK_CONTINUE

    # When aborting on a, we do not see c
    matches = rules.match(
        data='',
        which_callbacks=module.CALLBACK_ALL,
        callback=lambda v: callback('a', v)
    )
    assert len(received_values) == 1
    assert received_values[0]['rule'] == 'a'
    assert received_values[0]['matches']
    assert len(matches) == 1
    assert matches[0].rule == 'a'

    # When aborting on b, we do not see c either
    received_values = []
    matches = rules.match(
        data='',
        which_callbacks=module.CALLBACK_ALL,
        callback=lambda v: callback('b', v)
    )
    assert len(received_values) == 2
    assert received_values[0]['rule'] == 'a'
    assert received_values[0]['matches']
    assert received_values[1]['rule'] == 'b'
    assert not received_values[1]['matches']
    assert len(matches) == 1
    assert matches[0].rule == 'a'

    # Abort on d
    received_values = []
    matches = rules.match(
        data='',
        which_callbacks=module.CALLBACK_ALL,
        callback=lambda v: callback('c', v)
    )
    assert len(received_values) == 3
    assert received_values[0]['rule'] == 'a'
    assert received_values[0]['matches']
    assert received_values[1]['rule'] == 'b'
    assert not received_values[1]['matches']
    assert received_values[2]['rule'] == 'c'
    assert received_values[2]['matches']
    assert len(matches) == 2
    assert matches[0].rule == 'a'
    assert matches[1].rule == 'c'


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
def test_match_warnings_callback(module, is_yara):
    rules = module.compile(source="""
rule my_rule {
    strings:
        $s = "a"
    condition:
        any of them
}
""")

    # Limit is 1 000 000 in yara
    data = "a" * 1_000_010
    received_values = []
    def warnings_callback(warning_type, message):
        nonlocal received_values
        received_values.append((warning_type, message))
        return module.CALLBACK_CONTINUE

    matches = rules.match(data=data, warnings_callback=warnings_callback)

    assert len(received_values) == 1
    (warning_type, message) = received_values[0]
    assert warning_type == module.CALLBACK_TOO_MANY_MATCHES
    assert message.namespace == "default"
    assert message.rule == "my_rule"
    assert message.string == "$s"

    assert len(matches) == 1

    # It is also possible to abort
    # this does not work well in yara, it returns an "internal error: 30".
    # Lets ignore it, this is not a big deal.
    if not is_yara:
        received_values = []
        def warnings_callback(warning_type, message):
            nonlocal received_values
            received_values.append((warning_type, message))
            return module.CALLBACK_ABORT

        matches = rules.match(data=data, warnings_callback=warnings_callback)
        assert len(received_values) == 1
        assert len(matches) == 0


@pytest.mark.parametrize('module,is_yara', MODULES_DISTINCT)
def test_match_fast(module, is_yara):
    # Compile with a rule that can be evaluated without scanning rules
    rules = module.compile(source="""
rule my_rule {
    strings:
        $s = "a"
    condition:
        uint8(0) == 0x00 or any of them
}
""")

    with YaraCompatibilityMode():
        # In yara compat mode, all string matches are computed in all cases
        matches = rules.match(data=b"\x00 aa")
        assert len(matches) == 1
        m0 = matches[0]
        assert len(m0.strings) == 1
        s0 = m0.strings[0]
        assert len(s0.instances) == 2
        assert s0.instances[0].offset == 2
        assert s0.instances[0].matched_length == 1
        assert s0.instances[0].matched_data == b'a'
        assert s0.instances[1].offset == 3
        assert s0.instances[1].matched_length == 1
        assert s0.instances[1].matched_data == b'a'

        # When fast is enabled, matches are not always computed
        # Only check on boreal, how yara handles this flag is not that clear
        if not is_yara:
            matches = rules.match(data=b"\x00 aa", fast=True)
            assert len(matches) == 1
            m0 = matches[0]
            assert len(m0.strings) == 0

    # outside of compat mode, fast mode is the default
    if not is_yara:
        matches = rules.match(data=b"\x00 aa")
        assert len(matches) == 1
        m0 = matches[0]
        assert len(m0.strings) == 0


@pytest.mark.parametrize('module', MODULES)
def test_save_load(module):
    # Do not run the test if boreal was not compiled with the
    # serialize feature
    if not hasattr(boreal, 'load'):
        return

    # Compile with a rule that can be evaluated without scanning rules
    rules = module.compile(source="""
rule my_rule {
    strings:
        $s = "abc"
    condition:
        any of them
}
""")

    with tempfile.TemporaryDirectory() as fd:
        # Test save + load with filepath
        path = f"{fd}/file"
        rules.save(filepath=path)
        rules2 = module.load(filepath=path)
        matches = rules2.match(data=b"abc")
        assert len(matches) == 1

        # Test save + load with file
        path2 = f"{fd}/file2"
        with open(path2, "wb") as file:
            rules.save(file=file)
        with open(path2, "rb") as file:
            rules2 = module.load(file=file)
        matches = rules2.match(data=b"abc")
        assert len(matches) == 1


def test_save_load_bytes():
    # Yara does not support this, so only test on boreal

    rules = boreal.compile(source="""
rule my_rule {
    strings:
        $s = "abc"
    condition:
        any of them
}
""")

    data = rules.save(to_bytes=True)
    assert data is not None

    rules2 = boreal.load(data=data)
    matches = rules2.match(data=b"abc")
    assert len(matches) == 1


@pytest.mark.parametrize('module', MODULES)
def test_save_load_invalid_types(module):
    # Do not run the test if boreal was not compiled with the
    # serialize feature
    if not hasattr(boreal, 'load'):
        return

    # Compile with a rule that can be evaluated without scanning rules
    rules = module.compile(source="rule my_rule { condition: true }")

    with pytest.raises(TypeError):
        rules.save()
    with pytest.raises(TypeError):
        rules.save(filepath=1)
    with pytest.raises(TypeError):
        rules.save(file='str')

    with pytest.raises(TypeError):
        module.load()
    with pytest.raises(TypeError):
        module.load(filepath=1)
    with pytest.raises(TypeError):
        module.load(file='str')

    # Check the error if deserialization fails
    with tempfile.TemporaryDirectory() as fd:
        path = f"{fd}/file"
        with open(path, "wb") as f:
            f.write(b'invalid bytes')

        with pytest.raises(module.Error):
            module.load(filepath=path)

        with open(path, "rb") as f:
            with pytest.raises(module.Error):
                module.load(file=f)

        with open(path, "w") as f:
            with pytest.raises(module.Error):
                rules.save(file=f)


@pytest.mark.parametrize('module', MODULES)
def test_allow_duplicate_metadata(module):
    rules = module.compile(source="""
rule my_rule {
    meta:
        foo = "foo #1"
        foo = "foo #2"
        bar = "bar"
    condition:
        true
}""")

    with YaraCompatibilityMode():
        matches = rules.match(data="")
        r = matches[0]
        assert r.meta == {
            'foo': 'foo #2',
            'bar': 'bar'
        }

        matches = rules.match(data="", allow_duplicate_metadata=True)
        r = matches[0]
        assert r.meta == {
            'foo': ['foo #1', 'foo #2'],
            'bar': ['bar']
        }


def test_set_params():
    # Only run on boreal, yara does not support this
    rules = boreal.compile(source="""
rule a {
    strings:
        $ = "abc"
    condition:
        any of them
}""")

    # Simply check setting those parameters work. All those
    # parameters are properly tested in the boreal crate.
    rules.set_params(
        use_mmap=True,
        string_max_nb_matches=100,
        fragmented_scan_mode="fast",
        process_memory=False,
        max_fetched_region_size=100,
        memory_chunk_size=23,
    )

    with tempfile.NamedTemporaryFile() as fp:
        fp.write(b'dcabc <3>')
        fp.flush()
        matches = rules.match(filepath=fp.name)
        assert len(matches) == 1

    with pytest.raises(TypeError):
        rules.set_params(
            fragmented_scan_mode="unknown",
        )
