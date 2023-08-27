rule a {
    strings:
        $a = /a\é\^[1\23]/
    condition:
        $a
}

// [expected warning]: mem:3:16: warning: unknown escape sequence
// [expected warning]: mem:3:16: warning: a non ascii character is present in a regex
// [expected warning]: mem:3:22: warning: unknown escape sequence
