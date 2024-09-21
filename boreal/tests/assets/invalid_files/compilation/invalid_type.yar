// [error: expression has an invalid type]
rule a {
    condition:
        uint16("str") == 3
}
