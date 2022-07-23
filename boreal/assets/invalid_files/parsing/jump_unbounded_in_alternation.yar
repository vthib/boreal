rule a {
    strings:
        $a = { ( CD | AB [-] 85 ) }
    condition:
        $a
}
