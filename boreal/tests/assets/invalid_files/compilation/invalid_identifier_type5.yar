// [error: invalid identifier type]
import "pe"

rule c {
    condition:
        pe[2] == /aab/
}

