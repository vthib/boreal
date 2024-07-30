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

Parsing & compiling is not taken into account, only the scan in itself, using compiled rules.

Percentage displayed shows the differences between boreal and yara.

### File scan

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
  quality all tend to bring the performances closer to those of YARA.

### Process scan on Linux:

| Rules set \ File scanned                                                                             | containerd (71MB resident, 207MB scanned) | alacritty (110MB resident, 465MB scanned) |
| ---------------------------------------------------------------------------------------------------- | ----------------------------------------- | ----------------------------------------- |
| [orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 456 ms (-55%)                             | 2.02 s (-10%)                             |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 517 ms (-47%)                             | 2.19 s (+1.6%)                            |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | 511 ms (-53%)                             | 2.26 s (-17%)                             |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 925 ms  (+7%)                             | 1.92 s (-1.9%)                            |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 4.19 s (+13%)                             | 83 s   (+52%)                             |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | 517 ms (-40%)                             | 1.98 s (+1.1%)                            |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | 1.99 s (+35%)                             | 4.73 s (-4.7%)                            |

### Process scan on Windows:

| Rules set \ Process scanned                                                                          | chrome.exe (295MB private, 900MB scanned) | WavesSvc64.exe (217MB , 298MB scanned) |
| ---------------------------------------------------------------------------------------------------- | ----------------------------------------- | -------------------------------------- |
| [orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 2.30 s (-55%)                             | 931 ms (-73%)              |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 2.50 s (-51%)                             | 1.05 s (-63%)              |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | 2.83 s (-71%)                             | 1.35 s (-86%)              |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 1.82 s (-56%)                             | 661 ms (-65%)              |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             |  107 s  (+7%)                             | 13.4 s (-11%)              |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | 2.46 s (-60%)                             | 1.01 s (-77%)              |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | 7.40 s (-75%)                             | 3.44 s (-88%)              |

## Memory usage:

In `boreal`, different compiler profiles can be used, with one prioritizing scanning speed,
and the other one prioritzing memory usage. Those two profiles are presented separately to
show the memory consumption impact.

| rules set      | boreal (speed) | boreal (memory) | yara    |
| -------------- | -------------- | --------------- | ------- |
| orion          | 10.9 MB        | 9.71 MB         | 14.8 MB |
| atr            | 10.7 MB        | 8.53 MB         | 15.7 MB |
| reversinglabs  | 13.6 MB        | 12.2 MB         | 17.7 MB |
| panopticon     | 9.07 MB        | 7.71 MB         | 15.3 MB |
| c0ffee         | 16.7 MB        | 13.4 MB         | 198 MB  |
| icewater       | 61.6 MB        | 55.6 MB         | 56.3 MB |
| signature-base | 70.3 MB        | 44.2 MB         | 35.5 MB |
| yara-rules     | 99.3 MB        | 74.0 MB         | 45.4 MB |

Note that optimizing memory usage has not been a priority for the moment, as the focus was
on optimizing performances. However, the next release will provide a way to proritize
memory usage over scanning performances.
