// [error: wrong use of identifier]
rule a {
    condition: true
}

rule c {
    condition:
        a() == 2
}
