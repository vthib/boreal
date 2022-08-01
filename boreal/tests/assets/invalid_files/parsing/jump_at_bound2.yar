rule a {
    strings:
        $a = { ( CD EF | AB [-2] ) 85 }
    condition:
        $a
}
