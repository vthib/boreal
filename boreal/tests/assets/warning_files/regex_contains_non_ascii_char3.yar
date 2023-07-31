rule a {
    strings:
        $b = /ö*_∭/s wide
    condition: $b
}

// [expected warning]: mem:3:15: warning: a non ascii character is present in a regex
// [expected warning]: mem:3:18: warning: a non ascii character is present in a regex
