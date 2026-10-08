## How to run

```bash
# Retrieve all assets
./retrieve_assets.sh
# Run the benches
cargo bench
```

## Notes

Tests done on a Intel 7 265H with an SSD.
Measurements for scanning duration may vary significantly depending on hardware,
but the relative differences should stay relatively similar.

Percentage displayed shows the differences from YARA. The highlighted value is the best one.

## Scanning

#### [Orion](https://github.com/StrangerealIntel/Orion.git) (176 rules, 759 strings)

| File scanned           | YARA    | Boreal              | Yara-X          |
| ---------------------- | ------- | ------------------- | --------------- |
| vulkan-1.dll (737KiB)  | 6.08 ms | **1.04 ms (17.1%)** | 4.84 ms (79.6%) |
| libGLESv2.dll (5.5MiB) | 35.9 ms | **7.22 ms (20.1%)** | 36.4 ms (101%)  |
| firefox.msi (56MiB)    | 345 ms  | **37.1 ms (10.7%)** | 278 ms (80.6%)  |
| tests.exe (157MiB)     | 963 ms  | **176 ms (18.2%)**  | 827 ms (85.9%)  |

#### [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)

| File scanned           | YARA    | Boreal              | Yara-X          |
| ---------------------- | ------- | ------------------- | --------------- |
| vulkan-1.dll (737KiB)  | 5.66 ms | **1.29 ms (22.8%)** | 4.64 ms (82.1%) |
| libGLESv2.dll (5.5MiB) | 35.9 ms | **8.16 ms (22.7%)** | 34.8 ms (96.8%) |
| firefox.msi (56MiB)    | 323 ms  | **40.7 ms (12.6%)** | 257 ms (79.7%)  |
| tests.exe (157MiB)     | 938 ms  | **217 ms (23.1%)**  | 754 ms (80.3%)  |

#### [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (1240 rules, 1975 strings)

| File scanned           | YARA    | Boreal              | Yara-X          |
| ---------------------- | ------- | ------------------- | --------------- |
| vulkan-1.dll (737KiB)  | 21.8 ms | **3.88 ms (17.8%)** | 7.58 ms (34.9%) |
| libGLESv2.dll (5.5MiB) | 50 ms   | **14.4 ms (28.8%)** | 37.3 ms (74.6%) |
| firefox.msi (56MiB)    | 350 ms  | **41.2 ms (11.8%)** | 87.1 ms (24.9%) |
| tests.exe (157MiB)     | 1.54 s  | **380 ms (24.7%)**  | 898 ms (58.3%)  |

#### [panopticon](https://github.com/Neo23x0/panopticon) (100 rules, 1998 strings)

| File scanned           | YARA    | Boreal              | Yara-X          |
| ---------------------- | ------- | ------------------- | --------------- |
| vulkan-1.dll (737KiB)  | 4.1 ms  | **586 µs (14.3%)**  | 3.91 ms (95.4%) |
| libGLESv2.dll (5.5MiB) | 29.3 ms | **4 ms (13.6%)**    | 25.9 ms (88.4%) |
| firefox.msi (56MiB)    | 335 ms  | **37.6 ms (11.2%)** | 89.3 ms (26.7%) |
| tests.exe (157MiB)     | 889 ms  | **109 ms (12.2%)**  | 791 ms (89%)    |

#### [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (123 rules, 5390 strings)

| File scanned           | YARA   | Boreal               | Yara-X              |
| ---------------------- | ------ | -------------------- | ------------------- |
| vulkan-1.dll (737KiB)  | 213 ms | 216 ms (101%)        | **63.8 ms (29.9%)** |
| libGLESv2.dll (5.5MiB) | 727 ms | **313 ns (\<0.01%)** | 86.4 ms (11.9%)     |
| firefox.msi (56MiB)    | 847 ms | **311 ns (\<0.01%)** | 500 ms (59%)        |
| tests.exe (157MiB)     | 25.9 s | **313 ns (\<0.01%)** | 2.98 s (11.5%)      |

#### [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)

| File scanned           | YARA    | Boreal              | Yara-X               |
| ---------------------- | ------- | ------------------- | -------------------- |
| vulkan-1.dll (737KiB)  | 18.9 ms | **2.61 ms (13.8%)** | 3.06 ms (16.2%)      |
| libGLESv2.dll (5.5MiB) | 39.3 ms | **6.41 ms (16.3%)** | 11 ms (28%)          |
| firefox.msi (56MiB)    | 276 ms  | **47.4 ms (17.2%)** | 73.1 ms (26.5%)      |
| tests.exe (157MiB)     | 806 ms  | 1.98 ms (0.245%)    | **328 µs (0.0406%)** |

####  [signature-base](https://github.com/Neo23x0/signature-base) (5904 rules, 33166 strings)

| File scanned           | YARA    | Boreal              | Yara-X          |
| ---------------------- | ------- | ------------------- | --------------- |
| vulkan-1.dll (737KiB)  | 18.5 ms | **5.99 ms (32.3%)** | 11.5 ms (61.8%) |
| libGLESv2.dll (5.5MiB) | 71.4 ms | **36.6 ms (51.3%)** | 59.4 ms (83.2%) |
| firefox.msi (56MiB)    | 382 ms  | **178 ms (46.6%)**  | 285 ms (74.7%)  |
| tests.exe (157MiB)     | 1.99 s  | **962 ms (48.5%)**  | 1.47 s (74.1%)  |

## Compilation

### Compilation duration

Measure the time it takes to parse and compile all rules.

| Rules                                                                                                 | YARA        | Boreal             | Yara-X         |
| ----------------------------------------------------------------------------------------------------- | ----------- | ------------------ | -------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (176 rules, 759 strings)                       | **25.8 ms** | 35.9 ms (139%)     | 251 ms (972%)  |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)               | **35.5 ms** | 36.5 ms (103%)     | 238 ms (671%)  |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (1240 rules, 1975 strings) | **214 ms**  | 319 ms (149%)      | 2.12 s (992%)  |
| [panopticon](https://github.com/Neo23x0/panopticon) (100 rules, 1998 strings)                         | 12.7 ms     | **10 ms (79%)**    | 51.2 ms (403%) |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (123 rules, 5390 strings)                              | 6.18 s      | **223 ms (3.61%)** | 640 ms (10.4%) |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)              | **751 ms**  | 819 ms (109%)      | 13.5 s (1800%) |
| [signature-base](https://github.com/Neo23x0/signature-base) (5904 rules, 33166 strings)               | **595 ms**  | 657 ms (110%)      | 3.11 s (523%)  |

### Compilation size

Size of the compiled rules.

| Rules                                                                                                 | YARA         | Boreal               | Yara-X           |
| ----------------------------------------------------------------------------------------------------- | ------------ | -------------------- | ---------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (176 rules, 759 strings)                       | 12.2 MiB     | **0.80 MiB (6.56%)** | 2.64 MiB (21.6%) |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)               | 12.3 MiB     | **0.83 MiB (6.75%)** | 3.43 MiB (27.9%) |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (1240 rules, 1975 strings) | 14 MiB       | **4.28 MiB (30.6%)** | 10.1 MiB (72.1%) |
| [panopticon](https://github.com/Neo23x0/panopticon) (100 rules, 1998 strings)                         | 12.3 MiB     | **0.74 MiB (6.02%)** | 1.81 MiB (14.7%) |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (123 rules, 5390 strings)                              | 132 MiB      | **2.44 MiB (1.85%)** | 66.4 MiB (50.3%) |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)              | 36.2 MiB     | **18.0 MiB (49.7%)** | 49.4 MiB (136%)  |
| [signature-base](https://github.com/Neo23x0/signature-base) (5904 rules, 33166 strings)               | **28.6 MiB** | 48.6 MiB (170%)      | 29.4 MiB (103%)  |

## Rules serialization

### Serialization duration

Duration of the serialization of a scanner into bytes.

| Rules                                                                                                 | YARA    | Boreal              | Yara-X          |
| ----------------------------------------------------------------------------------------------------- | ------- | ------------------- | --------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (176 rules, 759 strings)                       | 290 µs  | **250 µs (86.2%)**  | 799 µs (275%)   |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)               | 513 µs  | **241 µs (47%)**    | 1.34 ms (261%)  |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (1240 rules, 1975 strings) | 3.82 ms | **3.43 ms (89.9%)** | 5.7 ms (149%)   |
| [panopticon](https://github.com/Neo23x0/panopticon) (100 rules, 1998 strings)                         | 369 µs  | **75.1 µs (20.4%)** | 758 µs (205%)   |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (123 rules, 5390 strings)                              | 82.5 ms | **842 µs (1.02%)**  | 47.8 ms (58%)   |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)              | 27.3 ms | **7.81 ms (28.6%)** | 22.7 ms (83.1%) |
| [signature-base](https://github.com/Neo23x0/signature-base) (5904 rules, 33166 strings)               | 16.1 ms | **8.1 ms (50.4%)**  | 18.9 ms (118%)  |

### Deserialization duration

Duration of the deserialization of bytes into a scanner.

| Rules                                                                                                 | YARA        | Boreal              | Yara-X          |
| ----------------------------------------------------------------------------------------------------- | ----------- | ------------------- | --------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (176 rules, 759 strings)                       | **477 µs**  | 1.77 ms (371%)      | 27.1 ms (5680%) |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)               | **991 µs**  | 2.11 ms (213%)      | 36.9 ms (3730%) |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (1240 rules, 1975 strings) | **4.1 ms**  | 10.2 ms (250%)      | 857 ms (20900%) |
| [panopticon](https://github.com/Neo23x0/panopticon) (100 rules, 1998 strings)                         | **813 µs**  | 1.83 ms (225%)      | 18 ms (2210%)   |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (123 rules, 5390 strings)                              | 202 ms      | **10.2 ms (5.07%)** | 163 ms (80.6%)  |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)              | 68.1 ms     | **11.1 ms (16.2%)** | 1.98 s (2910%)  |
| [signature-base](https://github.com/Neo23x0/signature-base) (5904 rules, 33166 strings)               | **45.7 ms** | 148 ms (325%)       | 1.17 s (2550%)  |


### Serialized size

Size of the serialized bytes.

| Rules                                                                                                 | YARA     | Boreal               | Yara-X               |
| ----------------------------------------------------------------------------------------------------- | -------- | -------------------- | -------------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (176 rules, 759 strings)                       | 575 KiB  | **292 KiB (50.7%)**  | 363 KiB (63.1%)      |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)               | 863 KiB  | **287 KiB (33.3%)**  | 601 KiB (69.7%)      |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (1240 rules, 1975 strings) | 3.84 MiB | **1.70 MiB (44.3%)** | 2.45 MiB (63.8%)     |
| [panopticon](https://github.com/Neo23x0/panopticon) (100 rules, 1998 strings)                         | 567 KiB  | **163 KiB (28.7%)**  | 297 KiB (52.4%)      |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (123 rules, 5390 strings)                              | 65.6 MiB | **693 KiB (1.03%)**  | 18.1 MiB (27.6%)     |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)              | 18.7 MiB | 9.55 MiB (51.0%)     | **6.89 MiB (36.8%)** |
| [signature-base](https://github.com/Neo23x0/signature-base) (5904 rules, 33166 strings)               | 15.6 MiB | **5.98 MiB (38.3%)** | 6.60 MiB (42.3%)     |

## Cost of `serialize` feature

| Rules                                                                                                 | without "serialize" feature | with "serialize" feature |
| ----------------------------------------------------------------------------------------------------- |---------------------------- | ------------------------ |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (176 rules, 759 strings)                       | 0.80 MiB                    | 0.85 MiB (106.1%)        |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)               | 0.83 MiB                    | 0.92 MiB (111.2%)        |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (1240 rules, 1975 strings) | 4.28 MiB                    | 4.51 MiB (105.5%)        |
| [panopticon](https://github.com/Neo23x0/panopticon) (100 rules, 1998 strings)                         | 0.74 MiB                    | 0.86 MiB (116.3%)        |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (123 rules, 5390 strings)                              | 2.44 MiB                    | 2.81 MiB (115.2%)        |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)              | 18.0 MiB                    | 18.9 MiB (104.8%)        |
| [signature-base](https://github.com/Neo23x0/signature-base) (5904 rules, 33166 strings)               | 48.6 MiB                    | 50.8 MiB (104.5%)        |
