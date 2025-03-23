// [error: identifier is not iterable]
rule z {
    condition: true
}

rule a {
    condition:
        for any a, b in z: (true)
}

