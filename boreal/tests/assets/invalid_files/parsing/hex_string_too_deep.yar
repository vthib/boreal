// [error: too many imbricated groups in the hex string]
// [no libyara conformance]
// Disabled on libyara as there isn't a depth limit afaict
rule a {
    strings:
        $a = { AA ( BB ( CC ( DD ( EE ( FF ( 00 ( 11 ( 22 ( 33 ( 44 ) 55 ) 66 ) 77 ) 88 ) 99 ) 01 ) 02 ) 03 ) 04 ) 05 }
    condition:
        $a
}
