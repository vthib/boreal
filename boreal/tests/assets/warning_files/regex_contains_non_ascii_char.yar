rule a {
    condition:
        /éç/
}

// [expected warning]: mem:3:10: warning: a non ascii character is present in a regex
// [expected warning]: mem:3:11: warning: a non ascii character is present in a regex
