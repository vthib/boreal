// [error: expected 1 identifiers to bind, got 2]
rule a {
    condition:
        for any k, v in (0..2): (true)
}

