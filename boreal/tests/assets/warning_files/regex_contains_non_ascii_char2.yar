rule a {
    condition: "a" matches /𩸽_⏫*_/
}

// [expected warning]: mem:2:29: warning: a non ascii character is present in a regex
// [expected warning]: mem:2:31: warning: a non ascii character is present in a regex
