// [error: identifier is not iterable]
import "pe"

rule z {
    condition: true
}

rule a {
    condition:
        for any a, b in z: (true)
}

