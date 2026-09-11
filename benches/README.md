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

#### [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X          |
| ---------------------- | ------- | ---------------------- | ----------------------- | --------------- |
| vulkan-1.dll (737KiB)  | 5.34 ms | **2.03 ms (38.1%)**    | 4.35 ms (81.5%)         | 3.86 ms (72.3%) |
| libGLESv2.dll (5.5MiB) | 32.8 ms | **15.5 ms (47.4%)**    | 34.4 ms (105%)          | 30.8 ms (93.8%) |
| firefox.msi (56MiB)    | 352 ms  | **197 ms (55.9%)**     | 374 ms (106%)           | 246 ms (69.9%)  |
| tests.exe (157MiB)     | 905 ms  | **447 ms (49.4%)**     | 1.04 s (115%)           | 669 ms (73.9%)  |

#### [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X             |
| ---------------------- | ------- | ---------------------- | ----------------------- | ------------------ |
| vulkan-1.dll (737KiB)  | 4.91 ms | **2.52 ms (51.3%)**    | 4.72 ms (96.1%)         | 3.75 ms (76.5%)    |
| libGLESv2.dll (5.5MiB) | 31.4 ms | **17.4 ms (55.4%)**    | 34.1 ms (108%)          | 28 ms (89%)        |
| firefox.msi (56MiB)    | 305 ms  | 213 ms (69.8%)         | 359 ms (118%)           | **202 ms (66.1%)** |
| tests.exe (157MiB)     | 848 ms  | **509 ms (60.1%)**     | 1.01 s (120%)           | 598 ms (70.5%)     |

#### [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X              |
| ---------------------- | ------- | ---------------------- | ----------------------- | ------------------- |
| vulkan-1.dll (737KiB)  | 11 ms   | **4.12 ms (37.4%)**    | 6.26 ms (56.9%)         | 5.46 ms (49.6%)     |
| libGLESv2.dll (5.5MiB) | 37.4 ms | **21.2 ms (56.8%)**    | 37.8 ms (101%)          | 29.6 ms (79.3%)     |
| firefox.msi (56MiB)    | 334 ms  | 203 ms (60.8%)         | 370 ms (111%)           | **53.2 ms (15.9%)** |
| tests.exe (157MiB)     | 1.12 s  | **636 ms (56.8%)**     | 1.15 s (103%)           | 719 ms (64.2%)      |

#### [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X              |
| ---------------------- | ------- | ---------------------- | ----------------------- | ------------------- |
| vulkan-1.dll (737KiB)  | 3.77 ms | **1.62 ms (42.9%)**    | 4.1 ms (109%)           | 3.08 ms (81.7%)     |
| libGLESv2.dll (5.5MiB) | 27.5 ms | **11.9 ms (43.2%)**    | 31.8 ms (116%)          | 20.4 ms (74.1%)     |
| firefox.msi (56MiB)    | 322 ms  | 151 ms (47%)           | 419 ms (130%)           | **55.5 ms (17.2%)** |
| tests.exe (157MiB)     | 828 ms  | **324 ms (39.1%)**     | 975 ms (118%)           | 628 ms (75.8%)      |

#### [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)

| File scanned           | YARA   | Boreal (speed profile) | Boreal (memory profile) | Yara-X              |
| ---------------------- | ------ | ---------------------- | ----------------------- | ------------------- |
| vulkan-1.dll (737KiB)  | 179 ms | 198 ms (111%)          | 201 ms (112%)           | **93.7 ms (52.4%)** |
| libGLESv2.dll (5.5MiB) | 610 ms | **189 ns (\<0.01%)**   | 189 ns (\<0.01%)        | 315 ms (51.6%)      |
| firefox.msi (56MiB)    | 704 ms | 191 ns (\<0.01%)       | **191 ns (\<0.01%)**    | 536 ms (76.1%)      |
| tests.exe (157MiB)     | 22 s   | **190 ns (\<0.01%)**   | 192 ns (\<0.01%)        | 11.8 s (53.4%)      |

#### [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X               |
| ---------------------- | ------- | ---------------------- | ----------------------- | -------------------- |
| vulkan-1.dll (737KiB)  | 14.9 ms | 8.01 ms (53.6%)        | 9.77 ms (65.4%)         | **2.53 ms (16.9%)**  |
| libGLESv2.dll (5.5MiB) | 34.6 ms | 22.2 ms (64.3%)        | 34.7 ms (100%)          | **7.61 ms (22%)**    |
| firefox.msi (56MiB)    | 256 ms  | 294 ms (115%)          | 367 ms (143%)           | **40.9 ms (16%)**    |
| tests.exe (157MiB)     | 745 ms  | 2.45 ms (0.329%)       | 2.71 ms (0.364%)        | **272 µs (0.0365%)** |

####  [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)

| File scanned           | YARA   | Boreal (speed profile) | Boreal (memory profile) | Yara-X              |
| ---------------------- | ------ | ---------------------- | ----------------------- | ------------------- |
| vulkan-1.dll (737KiB)  | 14 ms  | 14.9 ms (106%)         | 16.5 ms (118%)          | **10.2 ms (72.6%)** |
| libGLESv2.dll (5.5MiB) | 64 ms  | 64.5 ms (101%)         | 80.1 ms (125%)          | **50.8 ms (79.4%)** |
| firefox.msi (56MiB)    | 372 ms | 549 ms (148%)          | 541 ms (145%)           | **204 ms (54.9%)**  |
| tests.exe (157MiB)     | 1.77 s | 1.54 s (86.7%)         | 2.08 s (117%)           | **1.15 s (64.8%)**  |

## Compilation

### Compilation duration

Measure the time it takes to parse and compile all rules.

| Rules                                                                                                | YARA        | Boreal (speed profile) | Boreal (memory profile) | Yara-X         |
| ---------------------------------------------------------------------------------------------------- | ----------- | ---------------------- | ----------------------- | -------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | **17 ms**   | 28.9 ms (170%)         | 27.3 ms (161%)          | 149 ms (881%)  |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | **27.1 ms** | 34.7 ms (128%)         | 31.3 ms (115%)          | 176 ms (649%)  |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | **110 ms**  | 191 ms (173%)          | 187 ms (170%)           | 976 ms (884%)  |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 10.5 ms     | 11 ms (105%)           | **9.21 ms (88.1%)**     | 37.6 ms (360%) |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 5.12 s      | 167 ms (3.27%)         | **163 ms (3.19%)**      | 514 ms (10%)   |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | **601 ms**  | 610 ms (102%)          | 602 ms (100%)           | 9.83 s (1640%) |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | 267 ms      | 306 ms (115%)          | **241 ms (90.3%)**      | 1.42 s (533%)  |

### Compilation size

Size of the compiled rules.

| Rules                                                                                                | YARA     | Boreal (speed profile) | Boreal (memory profile) | Yara-X               |
| ---------------------------------------------------------------------------------------------------- | -------- | ---------------------- | ----------------------- | --------------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 12.2 MiB | 2.75 MiB (22.6%)       | **1.34 MiB (11%)**      | 2.64 MiB (21.7%)      |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 12.3 MiB | 3.65 MiB (29.6%)       | **1.58 MiB (12.8%)**    | 3.6 MiB (29.2%)       |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | 14 MiB   | 7.1 MiB (50.6%)        | **4.76 MiB (33.9%)**    | 10.6 MiB (75.7%)      |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 12.3 MiB | 2.5 MiB (20.3%)        | **1.07 MiB (8.75%)**    | 1.77 MiB (14.4%)      |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 132 MiB  | 6.62 MiB (5.03%)       | **3.26 MiB (2.47%)**    | 131 MiB (99.7%)       |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | 36.2 MiB | 25.1 MiB (69.5%)       | **19.1 MiB (52.7%)**    | 49.3 MiB (136%)       |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | 28.6 MiB | 73 MiB (255%)          | 39.9 MiB (140%)         | **30.2 MiB (106%)**   |

## Rules serialization

### Serialization duration

Duration of the serialization of a scanner into bytes.

| Rules                                                                                                | YARA        | Boreal                 | Yara-X          |
| ---------------------------------------------------------------------------------------------------- | ----------- | ---------------------- | --------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 169 µs      | **108 µs (63.6%)**     | 421 µs (249%)   |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 464 µs      | **210 µs (45.4%)**     | 896 µs (193%)   |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | **1.38 ms** | 1.80 ms (131%)         | 2.64 ms (192%)  |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 365 µs      | **77.7 µs (21.3%)**    | 327 ms (89.6%)  |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 115 ms      | **797 µs (0.69%)**     | 34.5 ms (29.9%) |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | 25.2 ms     | **11.0 ms (43.5%)**    | 14.0 ms (55.6%) |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | 12.9 ms     | **4.06 ms (31.3%)**    | 327 ms (89.7%)  |

Serialization performance in Boreal for the two profiles are identical, it does not depend on it.

### Deserialization duration

Duration of the deserialization of bytes into a scanner.

| Rules                                                                                                | YARA        | Boreal (speed profile) | Boreal (memory profile) | Yara-X           |
| ---------------------------------------------------------------------------------------------------- | ----------- | ---------------------- | ----------------------- | ---------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | **397 µs**  | 17.6 ms (4433%)        | 18.9 ms (4753%)         | 58.2 ms (14665%) |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | **911 µs**  | 7.60 ms (834%)         | 4.46 ms (489%)          | 112 ms (12280%)  |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | **2.00 ms** | 10.4 ms (521%)         | 8.95 ms (447%)          | 399 ms (19930%)  |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | **812 µs**  | 5.29 ms (652%)         | 3.50 ms (431%)          | 60.48 ms (7448%) |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 145 ms      | 13.99 ms (9.67%)       | **9.93 ms (6.87%)**     | 1.27 s (926%)    |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | **25.9 ms** | 44.8 ms (172%)         | 34.4 ms (132%)          | 1.33 s (5139%)   |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | **15.9 ms** | 159 ms (1002%)         | 109 ms (690%)           | 2.14 s (13499%)  |


### Serialized size

Size of the serialized bytes.

| Rules                                                                                                | YARA         | Boreal (speed profile) | Yara-X               |
| ---------------------------------------------------------------------------------------------------- | ------------ | ---------------------- | -------------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 492 KiB      | 302 KiB (61.4%)        | **267 KiB (54.1%)**  |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 856 KiB      | **301 KiB (35.2%)**    | 524 KiB (61.2%)      |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | 2.68 MiB     | **1.19 MiB (44.4%)**   | 1.56 MiB (58.2%)     |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 567 KiB      | **164 KiB (29.0%)**    | 226 KiB (39.9%)      |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 65.6 MiB     | **774 KiB (1.18%)**    | 19.6 MiB (29.9%)     |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | 18.7 MiB     | 13.0 MiB (69.6%)       | **6.48 MiB (34.6%)** |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | 9.87 MiB     | **3.67 MiB (37.2%)**   | 5.12 MiB (51.9%)     |

Serialization size in Boreal for the two profiles are identical, it does not depend on it.

## Cost of `serialize` feature

Speed profile:

| Rules                                                                                                | without "serialize" feature | with "serialize" feature |
| ---------------------------------------------------------------------------------------------------- |---------------------------- | ------------------------ |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 7.12 MiB                    | 7.35 MiB (103.3%)        |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 6.97 MiB                    | 7.11 MiB (102.0%)        |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | 9.8 MiB                     | 10.2 MiB (103.6%)        |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 5.23 MiB                    | 5.43 MiB (103.8%)        |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 14.2 MiB                    | 14.9 MiB (105.3%)        |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | 77.0 MiB                    | 80.4 MiB (104.4%)        |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | 103.4 MiB                   | 106.6 MiB (103.1%)       |

Memory profile:

| Rules                                                                                                | without "serialize" feature | with "serialize" feature |
| ---------------------------------------------------------------------------------------------------- |---------------------------- | ------------------------ |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 6.34 MiB                    | 6.57 MiB (103.7%)        |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 4.94 MiB                    | 5.07 MiB (102.8%)        |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | 8.60 MiB                    | 8.95 MiB (104.1%)        |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 4.20 MiB                    | 4.40 MiB (104.7%)        |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 11.4 MiB                    | 12.2 MiB (106.5%)        |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | 71.9 MiB                    | 75.3 MiB (104.7%)        |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | 78.1 MiB                    | 81.3 MiB (104.1%)        |
