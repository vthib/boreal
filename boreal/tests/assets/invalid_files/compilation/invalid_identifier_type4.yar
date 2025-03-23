// [error: invalid identifier type]
import "math"

rule c {
    condition:
        math() == /aab/
}
