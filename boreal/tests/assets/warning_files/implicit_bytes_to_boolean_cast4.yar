rule a {
    condition:
        for all i in (0..2) : (
            ""
        )
}

// [expected warning]: mem:4:13: warning: implicit cast from a bytes value to a boolean
