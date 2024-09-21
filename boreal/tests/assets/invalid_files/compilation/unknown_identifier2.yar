// [error: unknown identifier "foo"]
rule a {
    condition:
        for any a in foo: (true)
}
