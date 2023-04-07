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
| [orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 2.58 ms (-46%)       | 18.5 ms (-39%)        | 246 ms (-18%)      | 549 ms (-35%)     |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 3.65 ms (-19%)       | 25.4 ms (-15%)        | 297 ms (+4%)       | 756 ms (-4%)      |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | 6.62 ms (-34%)       | 29.9 ms (-14%)        | 272 ms (-7%)       | 1.13 s (+9%)      |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 2.20 ms (-36%)       | 18.4 ms (-27%)        | 180 ms (-38%)      | 492 ms (-37%)     |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 811 ms (-36%)        | 0.4 ms (-99%)         | 0.4 ms (-99%)      | 0.4 ms (-99%)     |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | 8.51 ms (-54%)       | 27.5 ms (-24%)        | 430 ms (+77%)      | 1.80 ms (-99.7%)  |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | 18.1 ms (+31%)       | 110 ms (+93%)         | 918 ms (+177%)     | 3.86 s (+134%)    |

A few observations:

- The few -99% are for cases where boreal detects that all rules can be computed without having to scan for strings. See [no scan optimization](#no-scan-optimization).
- Increase in number of strings, in file size, and decrease in strings quality all lead to deteriorating performances compared to YARA.
  This is somewhat expected as optimizations was not the main focus in development in early versions. Improving performances on
  all those cases is now however the priority.

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

Note that optimizing memory usage has not been a big focus, and optimizing performances will remain the main focus.
