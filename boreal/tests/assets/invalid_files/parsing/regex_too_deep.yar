// [error: too many imbricated groups in the regex]
// [no libyara conformance]
// Disabled on libyara as there isn't a depth limit afaict
rule a {
    strings:
        $a = /a(b|c(d(e((f(g(h(i(((1))|2)3|)|4)5)))67)8)9)/
    condition:
        $a
}
