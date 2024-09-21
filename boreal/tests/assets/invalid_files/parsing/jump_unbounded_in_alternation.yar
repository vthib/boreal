// [error: unbounded jumps not allowed inside alternations (|)]
rule a {
    strings:
        $a = { ( CD | AB [-] 85 ) }
    condition:
        $a
}
