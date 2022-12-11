// [no libyara conformance]
// Disabled on libyara as there isn't a depth limit afaict
rule a {
    condition:
        a.b(a.b(a.b(a.b(a.b(a.b(a.b(a.b(a.b(a.b())))))))))
}
