// [error: error converting to integer: number too large to fit in target type]
// [no libyara conformance]
// Test disabled against yara because of https://github.com/VirusTotal/yara/issues/1791,
// yara returning an error depends on the platform.
rule a {
    strings:
        $a = { AB [100000000000000000000000] CD }
    condition:
        $a
}

