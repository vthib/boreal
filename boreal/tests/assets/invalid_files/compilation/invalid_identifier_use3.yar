// [error: wrong use of identifier]
import "pe"

rule c {
    condition:
        pe == 2
}

