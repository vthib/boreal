// [error: unknown identifier "b*"]
rule a1 {
    condition: true
}
rule c {
    condition: all of (a*, b*)
}
