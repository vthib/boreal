use crate::libyara_compat::util::TEXT_1024_BYTES;
use crate::utils::{check, Checker};

const TEXT: &[u8] = TEXT_1024_BYTES.as_bytes();

fn make_rule(cond: &str) -> String {
    format!(
        r#"
import "hash"

rule test {{
    condition: {cond}
}}"#
    )
}

#[track_caller]
fn test(cond: &str, input: &[u8]) {
    check(&make_rule(cond), input, true);
}

#[test]
fn test_md5() {
    test(
        r#"hash.md5(0, filesize) == "0cc175b9c0f1b6a831c399e269772661""#,
        b"a",
    );
    test(
        r#"hash.md5(0, filesize) == "dcc824971a00e589619ba0c0bba41515""#,
        TEXT,
    );
    test(
        r#"hash.md5(50, 100) == "5c026f2a09609f79c46a7dab7398d4ac""#,
        TEXT,
    );

    test(
        r#"hash.md5("abcdefghijklmnopqrstuvwxyz") == "c3fcd3d76192e4007dfb496cca67e13b""#,
        b"",
    );
    test(
        r#"hash.md5(0, filesize) == "c3fcd3d76192e4007dfb496cca67e13b""#,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    // Instrument the cache
    test(
        "hash.md5(0, filesize) == hash.md5(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );
    test(
        "hash.md5(0, filesize * 2) == hash.md5(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );

    test(r#"not defined hash.md5(0, filesize)"#, b"");
    test(r#"not defined hash.md5(5, filesize)"#, b"a");
    test(r#"not defined hash.md5(-1, filesize)"#, b"a");
    test(r#"not defined hash.md5(0, -1)"#, b"a");

    // Test that fragmented memory still works if chunks are contiguous
    let mut checker = Checker::new(&make_rule(
        r#"hash.md5(50, 100) == "5c026f2a09609f79c46a7dab7398d4ac""#,
    ));
    checker.check_fragmented(&[(0, Some(TEXT))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..75])), (75, Some(&TEXT[75..150]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..75])), (75, Some(&TEXT[75..]))], true);
    checker.check_fragmented(
        &[
            (0, Some(&TEXT[0..50])),
            (50, Some(&TEXT[50..70])),
            (70, Some(&TEXT[70..130])),
            (130, Some(&TEXT[130..150])),
            (150, Some(&TEXT[150..])),
        ],
        true,
    );

    // Will still return a result if last region truncates the range
    let mut checker = Checker::new(&make_rule(
        r#"hash.md5(50, 200) == "5c026f2a09609f79c46a7dab7398d4ac""#,
    ));
    checker.check_fragmented(
        &[
            (0, Some(&TEXT[0..50])),
            (50, Some(&TEXT[50..70])),
            (70, Some(&TEXT[70..150])),
        ],
        true,
    );

    // Missing starting bytes of holes means undefined
    let mut checker = Checker::new(&make_rule("not defined hash.md5(50, 100)"));
    checker.check_fragmented(&[(0, Some(&TEXT[0..40])), (51, Some(&TEXT[51..]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..40])), (170, Some(&TEXT[170..]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..70])), (80, Some(&TEXT[80..]))], true);
}

#[test]
fn test_sha1() {
    test(
        r#"hash.sha1(0, filesize) == "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8""#,
        b"a",
    );
    test(
        r#"hash.sha1(0, filesize) == "ccb665bf4d6e19b56d3f70e9cc2837dfe3f3a745""#,
        TEXT,
    );
    test(
        r#"hash.sha1(50, 100) == "1d17cf1bd2c85210e088796fe302d08beb27dd5a""#,
        TEXT,
    );

    test(
        r#"hash.sha1("abcdefghijklmnopqrstuvwxyz") == "32d10c7b8cf96570ca04ce37f2a19d84240d3a89""#,
        b"",
    );
    test(
        r#"hash.sha1(0, filesize) == "32d10c7b8cf96570ca04ce37f2a19d84240d3a89""#,
        b"abcdefghijklmnopqrstuvwxyz",
    );
    // Instrument the cache
    test(
        "hash.sha1(0, filesize) == hash.sha1(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );
    test(
        "hash.sha1(0, filesize * 2) == hash.sha1(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );

    test(r#"not defined hash.sha1(0, filesize)"#, b"");
    test(r#"not defined hash.sha1(5, filesize)"#, b"a");
    test(r#"not defined hash.sha1(-1, filesize)"#, b"a");
    test(r#"not defined hash.sha1(0, -1)"#, b"a");

    // Test that fragmented memory still works if chunks are contiguous
    let mut checker = Checker::new(&make_rule(
        r#"hash.sha1(50, 100) == "1d17cf1bd2c85210e088796fe302d08beb27dd5a""#,
    ));
    checker.check_fragmented(&[(0, Some(TEXT))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..75])), (75, Some(&TEXT[75..150]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..75])), (75, Some(&TEXT[75..]))], true);
    checker.check_fragmented(
        &[
            (0, Some(&TEXT[0..50])),
            (50, Some(&TEXT[50..70])),
            (70, Some(&TEXT[70..130])),
            (130, Some(&TEXT[130..150])),
            (150, Some(&TEXT[150..])),
        ],
        true,
    );

    // Will still return a result if last region truncates the range
    let mut checker = Checker::new(&make_rule(
        r#"hash.sha1(50, 200) == "1d17cf1bd2c85210e088796fe302d08beb27dd5a""#,
    ));
    checker.check_fragmented(
        &[
            (0, Some(&TEXT[0..50])),
            (50, Some(&TEXT[50..70])),
            (70, Some(&TEXT[70..150])),
        ],
        true,
    );

    // Missing starting bytes of holes means undefined
    let mut checker = Checker::new(&make_rule("not defined hash.sha1(50, 100)"));
    checker.check_fragmented(&[(0, Some(&TEXT[0..40])), (51, Some(&TEXT[51..]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..40])), (170, Some(&TEXT[170..]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..70])), (80, Some(&TEXT[80..]))], true);
}

#[test]
fn test_sha256() {
    test(
        "hash.sha256(0, filesize) == \
            \"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\"",
        b"a",
    );
    test(
        "hash.sha256(0, filesize) == \
            \"62b33f9e7880055a0cb2f195e296f5c5f88043e08d5521199d1ae4f16df7b17b\"",
        TEXT,
    );
    test(
        "hash.sha256(50, 100) == \
            \"a8b65993e5cda9e8c6a93b8913062ae503df81cdebe0af070fd5ec3de4cf7dbf\"",
        TEXT,
    );

    test(
        "hash.sha256(\"abcdefghijklmnopqrstuvwxyz\") == \
            \"71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73\"",
        b"",
    );
    test(
        "hash.sha256(0, filesize) == \
            \"71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73\"",
        b"abcdefghijklmnopqrstuvwxyz",
    );
    // Instrument the cache
    test(
        "hash.sha256(0, filesize) == hash.sha256(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );
    test(
        "hash.sha256(0, filesize * 2) == hash.sha256(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );

    test(r#"not defined hash.sha256(0, filesize)"#, b"");
    test(r#"not defined hash.sha256(5, filesize)"#, b"a");
    test(r#"not defined hash.sha256(-1, filesize)"#, b"a");
    test(r#"not defined hash.sha256(0, -1)"#, b"a");

    // Test that fragmented memory still works if chunks are contiguous
    let mut checker = Checker::new(&make_rule(
        "hash.sha256(50, 100) == \
            \"a8b65993e5cda9e8c6a93b8913062ae503df81cdebe0af070fd5ec3de4cf7dbf\"",
    ));
    checker.check_fragmented(&[(0, Some(TEXT))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..75])), (75, Some(&TEXT[75..150]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..75])), (75, Some(&TEXT[75..]))], true);
    checker.check_fragmented(
        &[
            (0, Some(&TEXT[0..50])),
            (50, Some(&TEXT[50..70])),
            (70, Some(&TEXT[70..130])),
            (130, Some(&TEXT[130..150])),
            (150, Some(&TEXT[150..])),
        ],
        true,
    );

    // Will still return a result if last region truncates the range
    let mut checker = Checker::new(&make_rule(
        "hash.sha256(50, 200) == \
            \"a8b65993e5cda9e8c6a93b8913062ae503df81cdebe0af070fd5ec3de4cf7dbf\"",
    ));
    checker.check_fragmented(
        &[
            (0, Some(&TEXT[0..50])),
            (50, Some(&TEXT[50..70])),
            (70, Some(&TEXT[70..150])),
        ],
        true,
    );

    // Missing starting bytes of holes means undefined
    let mut checker = Checker::new(&make_rule("not defined hash.sha256(50, 100)"));
    checker.check_fragmented(&[(0, Some(&TEXT[0..40])), (51, Some(&TEXT[51..]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..40])), (170, Some(&TEXT[170..]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..70])), (80, Some(&TEXT[80..]))], true);
}

#[test]
fn test_checksum32() {
    test("hash.checksum32(0, filesize) == 97", b"a");
    test("hash.checksum32(0, filesize) == 52946", TEXT);
    test("hash.checksum32(50, 100) == 5215", TEXT);

    test(
        "hash.checksum32(\"abcdefghijklmnopqrstuvwxyz\") == 2847",
        b"",
    );
    test(
        "hash.checksum32(0, filesize) == 2847",
        b"abcdefghijklmnopqrstuvwxyz",
    );
    test(
        "hash.checksum32(0, filesize * 2) == hash.checksum32(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );

    test(r#"not defined hash.checksum32(0, filesize)"#, b"");
    test(r#"not defined hash.checksum32(5, filesize)"#, b"a");
    test(r#"not defined hash.checksum32(-1, filesize)"#, b"a");
    test(r#"not defined hash.checksum32(0, -1)"#, b"a");

    // Test that fragmented memory still works if chunks are contiguous
    let mut checker = Checker::new(&make_rule("hash.checksum32(50, 100) == 5215"));
    checker.check_fragmented(&[(0, Some(TEXT))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..75])), (75, Some(&TEXT[75..150]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..75])), (75, Some(&TEXT[75..]))], true);
    checker.check_fragmented(
        &[
            (0, Some(&TEXT[0..50])),
            (50, Some(&TEXT[50..70])),
            (70, Some(&TEXT[70..130])),
            (130, Some(&TEXT[130..150])),
            (150, Some(&TEXT[150..])),
        ],
        true,
    );

    // Will still return a result if last region truncates the range
    let mut checker = Checker::new(&make_rule("hash.checksum32(50, 200) == 5215"));
    checker.check_fragmented(
        &[
            (0, Some(&TEXT[0..50])),
            (50, Some(&TEXT[50..70])),
            (70, Some(&TEXT[70..150])),
        ],
        true,
    );

    // Missing starting bytes of holes means undefined
    let mut checker = Checker::new(&make_rule("not defined hash.checksum32(50, 100)"));
    checker.check_fragmented(&[(0, Some(&TEXT[0..40])), (51, Some(&TEXT[51..]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..40])), (170, Some(&TEXT[170..]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..70])), (80, Some(&TEXT[80..]))], true);
}

#[test]
fn test_crc32() {
    test("hash.crc32(0, filesize) == 0xe8b7be43", b"a");
    test("hash.crc32(0, filesize) == 0x74cb171", TEXT);
    test("hash.crc32(50, 100) == 0x25c34eec", TEXT);

    test(
        "hash.crc32(\"abcdefghijklmnopqrstuvwxyz\") == 0x4c2750bd",
        b"",
    );
    test(
        "hash.crc32(0, filesize) == 0x4c2750bd",
        b"abcdefghijklmnopqrstuvwxyz",
    );
    test(
        "hash.crc32(0, filesize * 2) == hash.crc32(0, filesize)",
        b"abcdefghijklmnopqrstuvwxyz",
    );

    test(r#"not defined hash.crc32(0, filesize)"#, b"");
    test(r#"not defined hash.crc32(5, filesize)"#, b"a");
    test(r#"not defined hash.crc32(-1, filesize)"#, b"a");
    test(r#"not defined hash.crc32(0, -1)"#, b"a");

    // Test that fragmented memory still works if chunks are contiguous
    let mut checker = Checker::new(&make_rule("hash.crc32(50, 100) == 0x25c34eec"));
    checker.check_fragmented(&[(0, Some(TEXT))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..75])), (75, Some(&TEXT[75..150]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..75])), (75, Some(&TEXT[75..]))], true);
    checker.check_fragmented(
        &[
            (0, Some(&TEXT[0..50])),
            (50, Some(&TEXT[50..70])),
            (70, Some(&TEXT[70..130])),
            (130, Some(&TEXT[130..150])),
            (150, Some(&TEXT[150..])),
        ],
        true,
    );

    // Will still return a result if last region truncates the range
    let mut checker = Checker::new(&make_rule("hash.crc32(50, 200) == 0x25c34eec"));
    checker.check_fragmented(
        &[
            (0, Some(&TEXT[0..50])),
            (50, Some(&TEXT[50..70])),
            (70, Some(&TEXT[70..150])),
        ],
        true,
    );

    // Missing starting bytes of holes means undefined
    let mut checker = Checker::new(&make_rule("not defined hash.crc32(50, 100)"));
    checker.check_fragmented(&[(0, Some(&TEXT[0..40])), (51, Some(&TEXT[51..]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..40])), (170, Some(&TEXT[170..]))], true);
    checker.check_fragmented(&[(0, Some(&TEXT[0..70])), (80, Some(&TEXT[80..]))], true);
}
