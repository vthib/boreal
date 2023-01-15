rule a {
    strings:
        $a = "aaa"
        $b = "bbb"
    condition:
        "foo" and for 2 of ($*) : (
            "bar"
        )
}

// [expected warning]: mem:6:9: warning: implicit cast from a bytes value to a boolean
// [expected warning]: mem:7:13: warning: implicit cast from a bytes value to a boolean
