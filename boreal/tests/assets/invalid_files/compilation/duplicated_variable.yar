// [error: variable $m is declared more than once]
rule a {
    strings:
        $m = /alg/
        $v = "chi"
        $m = { FF 00 }
    condition:
        all of them
}
