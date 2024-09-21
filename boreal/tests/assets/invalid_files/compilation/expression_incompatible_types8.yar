// [error: expressions have invalid types]
rule a {
    condition:
        for any i in ("a", "b"):
            (i >= 2)
}
