// [error: invalid identifier type]
import "math"

rule c {
    condition:
        math.MEAN_BYTES[2] == /aab/
}
