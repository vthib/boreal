// [error: a list of tokens cannot start or end with a jump]
rule a {
    strings:
        $a = { ( CD EF | AB [-2] ) 85 }
    condition:
        $a
}
