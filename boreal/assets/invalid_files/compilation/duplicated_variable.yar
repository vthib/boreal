rule a {
    strings:
        $m = /alg/
        $v = "chi"
        $m = { FF 00 }
    condition:
        all of them
}
