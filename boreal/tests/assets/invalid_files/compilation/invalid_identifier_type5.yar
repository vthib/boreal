// [error: invalid identifier type]
import "math"

rule c {
    condition:
        math[2] == /aab/
}

