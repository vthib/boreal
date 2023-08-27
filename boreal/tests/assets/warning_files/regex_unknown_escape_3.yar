rule a {
    strings:
        $a = /[\2-\i]/
    condition:
        $a
}

// [expected warning]: mem:3:16: warning: unknown escape sequence
// [expected warning]: mem:3:19: warning: unknown escape sequence
