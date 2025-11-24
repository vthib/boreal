## How to run

```bash
# Retrieve all assets
./retrieve-assets.sh
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

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X         |
| ---------------------- | ------- | ---------------------- | ----------------------- | -------------- |
| vulkan-1.dll (737KiB)  | 3.52 ms | **1.16 ms (32.9%)**    | 30.7 ms (87.2%)         | 3.96 ms (112%) |
| libGLESv2.dll (5.5MiB) | 23.4 ms | **8.81 ms (37.6%)**    | 24.1 ms (103%)          | 29.8 ms (127%) |
| firefox.msi (56MiB)    | 257 ms  | **113 ms (43.8%)**     | 271 ms (105%)           | 321 ms (125%)  |
| tests.exe (157MiB)     | 650 ms  | **249 ms (38.3%)**     | 732 ms (113%)           | 796 ms (123%)  |

#### [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X          |
| ---------------------- | ------- | ---------------------- | ----------------------- | --------------- |
| vulkan-1.dll (737KiB)  | 4.21 ms | **1.46 ms (34.7%)**    | 3.43 ms (81.7%)         | 3.44 ms (8.19%) |
| libGLESv2.dll (5.5MiB) | 22.9 ms | **10.3 ms (44.9%)**    | 24.3 ms (106%)          | 29.4 ms (128%)  |
| firefox.msi (56MiB)    | 231 ms  | **131 ms (56.7%)**     | 259 ms (112%)           | 311 ms (135%)   |
| tests.exe (157MiB)     | 632 ms  | **296 ms (46.8%)**     | 749 ms (118%)           | 794 ms (125%)   |

#### [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X           |
| ---------------------- | ------- | ---------------------- | ----------------------- | ---------------- |
| vulkan-1.dll (737KiB)  | 6.36 ms | **2.21 ms (34.7%)**    | 4.12 ms (64.7%)         | 5.37 ms (84.4%)  |
| libGLESv2.dll (5.5MiB) | 25.9 ms | **11.8 ms (45.6%)**    | 25.8 ms (99.6%)         | 24.2 ms (93.4%)  |
| firefox.msi (56MiB)    | 252 ms  | **122 ms (48.4%)**     | 265 ms (10.5%)          | 184 ms (73%)     |
| tests.exe (157MiB)     | 774 ms  | **347 ms (44.8%)**     | 797 ms (103%)           | 646 ms (83.4%)   |

#### [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X         |
| ---------------------- | ------- | ---------------------- | ----------------------- | -------------- |
| vulkan-1.dll (737KiB)  | 2.75 ms | **0.98 ms (35.9%)**    | 3.19 ms (112.7%)        | 3.5 ms (127%)  |
| libGLESv2.dll (5.5MiB) | 20.4 ms | **7.49 ms (36.7%)**    | 24.7 ms (121%)          | 25.7 ms (126%) |
| firefox.msi (56MiB)    | 244 ms  | **85.8 ms (35.2%)**    | 319 ms (131%)           | 324 ms (133%)  |
| tests.exe (157MiB)     | 616 ms  | **202 ms (32.8%)**     | 752 ms (121%)           | 783 ms (127%)  |

#### [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)

| File scanned           | YARA   | Boreal (speed profile) | Boreal (memory profile) | Yara-X              |
| ---------------------- | ------ | ---------------------- | ----------------------- | ------------------- |
| vulkan-1.dll (737KiB)  | 89  ms | 81.6 ms (90.8%)        | 82.5 ms (91.8%)         | **52.8 ms (58.6%)** |
| libGLESv2.dll (5.5MiB) | 311 ms | **0.1 ms (0.04%)**     | **0.3 ms (0.04%)**      | 208 ms (65.8%)      |
| firefox.msi (56MiB)    | 468 ms | **0.1 ms (0.04%)**     | **0.3 ms (0.04%)**      | 875 ms (187%)       |
| tests.exe (157MiB)     | 11.5 s | **0.1 ms (\<0.01%)**   | **0.3 ms (\<0.01%)**    | 7.26 s (62.8%)      |

#### [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)

| File scanned           | YARA       | Boreal (speed profile) | Boreal (memory profile) | Yara-X              |
| ---------------------- | ---------- | ---------------------- | ----------------------- | ------------------- |
| vulkan-1.dll (737KiB)  | 9.18 ms    | 5.42 ms (59%)          | 6.79 ms (73.9%)         | **4.08 ms (44.4%)** |
| libGLESv2.dll (5.5MiB) | 23.4 ms    | **13.4 ms (57.2%)**    | 23.3 ms (99.6%)         | 22 ms (94%)         |
| firefox.msi (56MiB)    | 173 ms     | **156 ms (90.2%)**     | 175 ms (101.2%)         | 233 ms (135%)       |
| tests.exe (157MiB)     | 537 ms     | 1.47 ms (0.27%)        | 1.46 ms (0.27%)         | **0.26 ms (0.05%)** |

####  [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)

| File scanned           | YARA       | Boreal (speed profile) | Boreal (memory profile) | Yara-X           |
| ---------------------- | ---------- | ---------------------- | ----------------------- | ---------------- |
| vulkan-1.dll (737KiB)  | 7.48 ms    | **5.16 ms (68.98%)**   | 8.02 ms (107.2%)        | 7.25 ms (96.9%)  |
| libGLESv2.dll (5.5MiB) | 36.3 ms    | **28.9 ms (79.6%)**    | 46.9 ms (129.2%)        | 44.1 ms (121.4%) |
| firefox.msi (56MiB)    | **219 ms** | 281 ms (128.3%)        | 381 ms (174.0%)         | 236 ms (107.7%)  |
| tests.exe (157MiB)     | 1.02 s     | **728 ms (71.02%)**    | 1.33 ms (130.0%)        | 1.04 s (101.6%)  |

## Compilation

### Compilation duration

Measure the time it takes to parse and compile all rules.

| Rules                                                                                                | YARA        | Boreal (speed profile) | Boreal (memory profile) | Yara-X          |
| ---------------------------------------------------------------------------------------------------- | ----------- | ---------------------- | ----------------------- | --------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | **28.5 ms** | 62.5 ms (219%)         | 60.6 ms (213%)          | 139.5 ms (489%) |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | **38.4 ms** | 48.4 ms (126.3%)       | 45.1 ms (117.5%)        | 221 ms (577%)   |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | **159 ms**  | 340 ms (214%)          | 337 ms (212%)           | 1.02 s (644%)   |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | **9.67 ms** | 12.2 ms (126.2%)       | 10.6 ms (109.6%)        | 84.9 ms (879%)  |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 4.95 s      | 123 ms (2.5%)          | **111 ms (2.2%)**       | 1.54 s (31.1%)  |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | **1.39 s**  | 1.50 s (107.9%)        | 1.49 s (106.9%)         | 3.57 s (256%)   |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | **313 ms**  | 347 ms (110.8%)        | 315 ms (100.7%)         | 2.70 s (864%)   |

### Compilation size

Size of the compiled rules.

| Rules                                                                                                | YARA         | Boreal (speed profile) | Boreal (memory profile) | Yara-X           |
| ---------------------------------------------------------------------------------------------------- | ------------ | ---------------------- | ----------------------- | ---------------- |
| [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 12.8 MiB     | 7.4 MiB (57.7%)        | **6.55 MiB (51.1%)**    | 8.62 MiB (67.2%) |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 13.5 MiB     | 6.97 MiB (51.6%)       | **4.94 MiB (36.6%)**    | 23.2 MiB (172%)  |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | 15.2 MiB     | 10.4 MiB (68.4%)       | **8.7 MiB (57.4%)**     | 56.7 MiB (373%)  |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 12.7 MiB     | 5.23 MiB (41.2%)       | **4.2 MiB (33.1%)**     | 7.51 MiB (59.3%) |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 171 MiB      | 14.2 MiB (8.3%)        | **11.4 MiB (6.69%)**    | 558 MiB (327%)   |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | **54.0 MiB** | 77.0 MiB (142%)        | 71.9 MiB (133%)         | 68.2 MiB (126%)  |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | **30.7 MiB** | 102 MiB (332%)         | 75.6 MiB (246%)         | 84.1 MiB (273%)  |

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
