use crate::utils::check;

#[test]
fn test_math() {
    check(
        "import \"math\"
      rule test {
        condition:
          math.min(0, 1) == 0
      }",
        b"A",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.max(0, 1) == 1
      }",
        b"A",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.to_number(1 == 1)
      }",
        b"A",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.to_number(1 > 2)
      }",
        b"A",
        false,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.abs(-1) == 1
      }",
        b"A",
        true,
    );

    check(
        "import \"math\"
      rule test {
        strings:
          $a = \"A\"
          $b = \"B\"
        condition:
          math.abs(@a - @b) == 1
      }",
        b"AB",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.count(0x41, 0, 3) == 2
      }",
        b"AABAAB",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.count(0x41) == 2
      }",
        b"ABAB",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.percentage(0x41) > 0.39 and math.percentage(0x41) < 0.41
      }",
        b"ABAB\0",
        true,
    ); // Blob matching includes terminating zero byte

    check(
        "import \"math\"
      rule test {
        condition:
          math.percentage(0x41, 0, 4) == 0.5
      }",
        b"ABABCDEF",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.mode() == 0x41
      }",
        b"ABABA",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.mode(2, 3) == 0x41
      }",
        b"CCABACC",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.entropy(\"AAAAA\") == 0.0
      }",
        b"",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.entropy(\"AABB\") == 1.0
      }",
        b"",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.entropy(2, 3) == 0.0
      }",
        b"CCAAACC",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.deviation(\"AAAAA\", 0.0) == 65.0
      }",
        b"",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.deviation(\"ABAB\", 65.0) == 0.5
      }",
        b"",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.deviation(2, 4, 65.0) == 0.5
      }",
        b"ABABABAB",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.mean(\"ABCABC\") == 66.0
      }",
        b"",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.mean(0, 3) == 66.0
      }",
        b"ABCABC",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.serial_correlation(\"BCAB\") == -0.5
      }",
        b"",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.serial_correlation(1, 4) == -0.5
      }",
        b"ABCABC",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.in_range(2.0, 1.0, 3.0)
      }",
        b"",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.in_range(6.0, 1.0, 3.0)
      }",
        b"",
        false,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.monte_carlo_pi(\"ABCDEF123456987\") < 0.3
      }",
        b"",
        true,
    );

    check(
        "import \"math\"
      rule test {
        condition:
          math.monte_carlo_pi(3, 15) < 0.3
      }",
        b"123ABCDEF123456987DE",
        true,
    );
}
