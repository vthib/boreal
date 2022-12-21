use crate::utils::check;

#[test]
fn test_string() {
    check(
        "import \"string\"
      rule test {
        condition:
          string.to_int(\"1234\") == 1234
      }",
        b"",
        true,
    );

    check(
        "import \"string\"
      rule test {
        condition:
          string.to_int(\"-1\") == -1
      }",
        b"",
        true,
    );

    // Leading spaces and + are allowed.
    check(
        "import \"string\"
      rule test {
        condition:
          string.to_int(\" +1\") == 1
      }",
        b"",
        true,
    );

    // Strings can be prefixed with 0x and will be interpreted as hexadecimal.
    check(
        "import \"string\"
      rule test {
        condition:
          string.to_int(\"0x10\") == 16
      }",
        b"",
        true,
    );

    // Strings prefixed with 0 will be interpreted as octal.
    check(
        "import \"string\"
      rule test {
        condition:
          string.to_int(\"010\") == 8
      }",
        b"",
        true,
    );

    check(
        "import \"string\"
      rule test {
        condition:
          string.to_int(\"10\", 8) == 8
      }",
        b"",
        true,
    );

    // Base 0 is a special case that tries to interpret the string by prefix, or
    // default to decimal. We aren't doing anything special to get this, it is
    // part of strtoll by default.
    check(
        "import \"string\"
      rule test {
        condition:
          string.to_int(\"010\", 0) == 8 and
          string.to_int(\"0x10\", 0) == 16 and
          string.to_int(\"10\", 0) == 10
      }",
        b"",
        true,
    );

    // Test undefined cases

    // on invalid base value
    check(
        "import \"string\"
      rule test {
        condition:
          not defined string.to_int(\"1\", -1) and
          not defined string.to_int(\"1\", 1) and
          not defined string.to_int(\"1\", 37)
      }",
        b"",
        true,
    );

    // on underflow or underflow
    check(
        "import \"string\"
      rule test {
        condition:
          not defined string.to_int(\"9223372036854775808\")
      }",
        b"",
        true,
    );
    check(
        "import \"string\"
      rule test {
        condition:
          not defined string.to_int(\"-9223372036854775809\")
      }",
        b"",
        true,
    );

    // if parsing does not use all the string
    check(
        "import \"string\"
      rule test {
        condition:
          not defined string.to_int(\"FOO\") and
          not defined string.to_int(\"10A20\")
      }",
        b"",
        true,
    );

    // if parsing does not consume any digits
    check(
        "import \"string\"
      rule test {
        condition:
          not defined string.to_int(\"\") and
          not defined string.to_int(\"   -\") and
          not defined string.to_int(\" +0x\")
      }",
        b"",
        true,
    );

    check(
        "import \"string\"
      rule test {
        condition:
          string.length(\"AXS\\x00ERS\") == 7
      }",
        b"",
        true,
    );
}
