## How to run

```bash
# Retrieve all assets
./retrieve-assets.sh
# Run the benches
cargo bench
```

## Scan duration

Tests done on a i7-10750H with an SSD.

- Boreal compiled with `--release --features authenticode`
- Yara used through yara-rust

Parsing & compiling is not taken into account, only the scanning of a file, using
compiled rules.

Percentage displayed shows the differences between boreal and yara.

| Rules set \ File scanned                                                                             | vulkan-1.dll (737KB) | libGLESv2.dll (5.5MB) | firefox.msi (56MB) | tests.exe (157MB) |
| ---------------------------------------------------------------------------------------------------- | -------------------- | --------------------- | ------------------ | ----------------- |
| [orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 1.89 ms (-62%)       | 13.3 ms (-58%)        | 154 ms (-51%)      | 386 ms (-54%)     |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 2.44 ms (-51%)       | 15.5 ms (-50%)        | 185 ms (-38%)      | 452 ms (-44%)     |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | 4.92 ms (-54%)       | 19.4 ms (-47%)        | 155 ms (-49%)      | 561 ms (-49%)     |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 1.57 ms (-57%)       | 11.2 ms (-57%)        | 122 ms (-60%)      | 310 ms (-61%)     |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             |  169 ms (-4%)        |  0.2 ms (-99%)        | 0.2 ms (-99%)      | 0.2 ms (-99%)     |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | 6.20 ms (-60%)       | 18.4 ms (-48%)        | 256 ms (+5%)       | 463 ms (-35%)     |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | 13.6 ms (+12%)       | 43.1 ms (-19%)        | 385 ms (+27%)      | 1.17 s (-23%)     |

A few observations:

- The few -99% are for cases where boreal detects that all rules can be
  computed without having to scan for strings.
  See [no scan optimization](/boreal/README.md#no-scan-optimization).
- Increase in number of strings, in file size, and decrease in strings
  quality all lead to deteriorating performances compared to YARA.
  This is somewhat expected as optimizations was not the main focus in
  development in early versions. Improving performances on all those cases
  is now however the priority.

## Memory usage:

| rules set      | boreal  | yara   |
| -------------- | ----    | ----   |
| orion          | 12.8 MB | 12.3MB |
| atr            | 12.6 MB | 14.0MB |
| reversinglabs  | 14.9 MB | 15.8MB |
| panopticon     | 10.9 MB | 13.4MB |
| c0ffee         | 22.9 MB | 200MB  |
| icewater       | 77.9 MB | 55.1MB |
| signature-base | 78.9 MB | 27.8MB |

Note that optimizing memory usage has not been a priority for the moment, as the focus was
on optimizing performances. However, the next release will provide a way to proritize
memory usage over scanning performances.
