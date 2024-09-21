// [error: expressions have invalid types]
rule a {
    condition:
        15 + "foo" == 3
}
