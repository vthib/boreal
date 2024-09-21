// [error: expression has an invalid type]
rule a {
    condition:
        for any i in (true, false): (i)
}
