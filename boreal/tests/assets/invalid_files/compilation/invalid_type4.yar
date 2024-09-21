// [error: expression has an invalid type]
rule a {
    condition:
        for any i in (1, 2, 3):
            (i startswith "a")
}
