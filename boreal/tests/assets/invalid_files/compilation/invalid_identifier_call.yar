// [error: invalid arguments types: [integer]]
import "math"

rule a {
    condition:
        math.to_number(2) == 3
}
