// [error: rule "a125" matches a previous rule set "a*"]
rule a0 {
    condition:
        true
}

rule b {
    condition:
        all of (a*)
}

rule a125 {
    condition: true
}
