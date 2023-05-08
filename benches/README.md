## How to run

```bash
# Retrieve all assets
./retrieve-assets.sh
# Run the benches
cargo run --features openssl,bench
```

## Scan duration

Tests done on a i7-10750H with an SSD.

- Boreal compiled with `--release --features openssl`
- Yara used through yara-rust

Parsing & compiling is not taken into account, only the scanning of a file, using
compiled rules.

Percentage displayed shows the differences between boreal and yara.

| Rules set \ File scanned                                                                             | vulkan-1.dll (737KB) | libGLESv2.dll (5.5MB) | firefox.msi (56MB) | tests.exe (157MB) |
| ---------------------------------------------------------------------------------------------------- | -------------------- | --------------------- | ------------------ | ----------------- |
| [orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 1.89 ms (-62%)       | 13.3 ms (-58%)        | 163 ms (-49%)      | 365 ms (-57%)     |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 2.74 ms (-45%)       | 17.6 ms (-40%)        | 188 ms (-37%)      | 503 ms (-38%)     |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | 5.36 ms (-50%)       | 22.7 ms (-38%)        | 181 ms (-42%)      | 663 ms (-38%)     |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 1.57 ms (-57%)       | 14.4 ms (-45%)        | 122 ms (-60%)      | 337 ms (-58%)     |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             |  684 ms (+284%)      |  0.2 ms (-99%)        | 0.2 ms (-99%)      | 0.2 ms (-99%)     |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | 6.57 ms (-60%)       | 18.7 ms (-45%)        | 274 ms (+13%)      | 477 ms (-34%)     |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | 12.2 ms (+11%)       | 55.2 ms (+3%)         | 406 ms (+27%)      | 1.67 s (+8%)      |

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
| orion          | 17.5 MB | 13.6MB |
| atr            | 15.8 MB | 14.0MB |
| reversinglabs  | 116 MB  | 15.8MB |
| panopticon     | 5.5 MB  | 13.9MB |
| c0ffee         | 96 MB   | 185MB  |
| icewater       | 78 MB   | 54.8MB |
| signature      | 134 MB  | 32MB   |

Note that optimizing memory usage has not been a big focus, and optimizing
performances will remain the main focus.
