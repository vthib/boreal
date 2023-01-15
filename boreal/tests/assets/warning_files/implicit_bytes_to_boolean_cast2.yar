rule a {
    condition:
        true and "foo"
}

// [expected warning]: mem:3:18: warning: implicit cast from a bytes value to a boolean
