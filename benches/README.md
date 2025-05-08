## How to run

```bash
# Retrieve all assets
./retrieve-assets.sh
# Run the benches
cargo bench
```

## Notes

Tests done on a Ryzen 3900X with an SSD.
Measurements for scanning duration may vary significantly depending on hardware,
but the relative differences should stay relatively similar.

Percentage displayed shows the differences from YARA. The highlighted value is the best one.

## Scanning

Tests done on a Ryzen 3900X with an SSD. Timings may vary significantly depending on hardware,
but the relative differences should stay relatively similar.

Parsing & compiling is not taken into account, only the scan in itself, using compiled rules.

Percentage displayed shows the differences from YARA.

#### [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X           |
| ---------------------- | ------- | ---------------------- | ----------------------- | ---------------- |
| vulkan-1.dll (737KiB)  | 4.82 ms | **1.82 ms (37,7%)**    | 4.22 ms (87.5%)         | 5.50 ms (114%)   |
| libGLESv2.dll (5.5MiB) | 31.3 ms | **12.9 ms (41.2%)**    | 32.4 ms (103.6%)        | 41.2 ms (131.6%) |
| firefox.msi (56MiB)    | 332 ms  | **149 ms (44.7%)**     | 345 ms (103.7%)         | 416 ms (125.4%)  |
| tests.exe (157MiB)     | 853 ms  | **384 ms (45%)**       | 959 ms (112.4%)         | 1.08 s (127%)    |

#### [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X           |
| ---------------------- | ------- | ---------------------- | ----------------------- | ---------------- |
| vulkan-1.dll (737KiB)  | 5.01 ms | **2.44 ms (48.7%)**    | 4.65 ms (92.8%)         | 5.28 ms (105.4%) |
| libGLESv2.dll (5.5MiB) | 31.9 ms | **16.5 ms (51.9%)**    | 33 ms (103.6%)          | 40.7 ms (127.8%) |
| firefox.msi (56MiB)    | 307 ms  | **188 ms (61.2%)**     | 323 ms (105.4%)         | 390 ms (127.2%)  |
| tests.exe (157MiB)     | 862 ms  | **483 ms (56.1%)**     | 975 ms (113%)           | 1.15 s (118%)    |

#### [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X           |
| ---------------------- | ------- | ---------------------- | ----------------------- | ---------------- |
| vulkan-1.dll (737KiB)  | 10.9 ms | **4.9 ms (44.7%)**     | 7.43 ms (67.8%)         | 8.75 ms (79.9%)  |
| libGLESv2.dll (5.5MiB) | 37.8 ms | **19.6 ms (51.9%)**    | 38.5 ms (101.8%)        | 35.7 ms (94.3%)  |
| firefox.msi (56MiB)    | 322 ms  | **161 ms (50.0%)**     | 376 ms (117.1%)         | 235.1 ms (73.1%) |
| tests.exe (157MiB)     | 1.16 s  | **552 ms (49.5%)**     | 1.15 s (102.9%)         | 941 ms (84.3%)   |

#### [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)

| File scanned           | YARA    | Boreal (speed profile) | Boreal (memory profile) | Yara-X           |
| ---------------------- | ------- | ---------------------- | ----------------------- | ---------------- |
| vulkan-1.dll (737KiB)  | 3.72 ms | **1.58 ms (42.5%)**    | 4.29 ms (115.3%)        | 4.85 ms (79.9%)  |
| libGLESv2.dll (5.5MiB) | 27.8 ms | **10.7 ms (38.7%)**    | 31.1 ms (112%)          | 32.7 ms (94.3%)  |
| firefox.msi (56MiB)    | 318 ms  | **122 ms (38.4%)**     | 415 ms (130.3%)         | 400.9 ms (73.1%) |
| tests.exe (157MiB)     | 802 ms  | **297 ms (37.1%)**     | 947 ms (102.9%)         | 941 ms (84.3%)   |

#### [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)

| File scanned           | YARA   | Boreal (speed profile) | Boreal (memory profile) | Yara-X             |
| ---------------------- | ------ | ---------------------- | ----------------------- | ------------------ |
| vulkan-1.dll (737KiB)  | 202 ms | 167 ms (82.78%)        | 169 ms (84.1%)          | **122 ms (60.4%)** |
| libGLESv2.dll (5.5MiB) | 669 ms | **0.3 ms (0.04%)**     | **0.3 ms (0.04%)**      | 482 ms (72.1%)     |
| firefox.msi (56MiB)    | 693 ms | **0.3 ms (0.04%)**     | **0.3 ms (0.04%)**      | 1.33 s (192%)      |
| tests.exe (157MiB)     | 22.7 s | **0.3 ms (\<0.01%)**   | **0.3 ms (\<0.01%)**    | 15.7 s (69.2%)     |

#### [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)

| File scanned           | YARA       | Boreal (speed profile) | Boreal (memory profile) | Yara-X              |
| ---------------------- | ---------- | ---------------------- | ----------------------- | ------------------- |
| vulkan-1.dll (737KiB)  | 18.7 ms    | 8.39 ms (44.9%)        | 10.5 ms (56.2%)         | **5.02 ms (26.9%)** |
| libGLESv2.dll (5.5MiB) | 39.2 ms    | **21.5 ms (54.9%)**    | 34.5 ms (88.0%)         | 29.7 ms (75.7%)     |
| firefox.msi (56MiB)    | **265 ms** | 267 ms (100.7%)        | 314 ms (118.6%)         | 333 s (126%)        |
| tests.exe (157MiB)     | 746 ms     | 2.99 ms (0.40%)        | 3.45 ms (0.46%)         | **0.26 ms (0.03%)** |

####  [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)

| File scanned           | YARA       | Boreal (speed profile) | Boreal (memory profile) | Yara-X              |
| ---------------------- | ---------- | ---------------------- | ----------------------- | ------------------- |
| vulkan-1.dll (737KiB)  | 12.9 ms    | 15.8 ms (122.5%)       | 17.9 ms (139.4%)        | **11.7 ms (90.8%)** |
| libGLESv2.dll (5.5MiB) | 58.3 ms    | **49.1 ms (84.3%)**    | 65.8 ms (112.9%)        | 65 ms (111.5%)      |
| firefox.msi (56MiB)    | **336 ms** | 429 ms (127.9%)        | 505 ms (150.3%)         | 404 ms (120.3%)     |
| tests.exe (157MiB)     | 1.68 s     | **1.31 s (77.8%)**     | 1.83 ms (109.1%)        | 1.64 s (97.4%)      |

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
| [Orion](https://github.com/StrangerealIntel/Orion.git) (147 rules, 644 strings)                      | 12.8 MiB     | 7.12 MiB (55.5%)       | **6.34 MiB (49.4%)**    | 6.59 MiB (132%)  |
| [atr](https://github.com/advanced-threat-research/Yara-Rules) (167 rules, 1408 strings)              | 13.5 MiB     | 6.97 MiB (51.6%)       | **4.94 MiB (36.6%)**    | 23.5 MiB (174%)  |
| [reversinglabs](https://github.com/reversinglabs/reversinglabs-yara-rules) (632 rules, 1536 strings) | 15.2 MiB     | 9.8 MiB (64.5%)        | **8.6 MiB (56.6%)**     | 34.4 MiB (227%)  |
| [panopticon](https://github.com/Neo23x0/panopticon) (180 rules, 1998 strings)                        | 12.7 MiB     | 5.23 MiB (41.2%)       | **4.2 MiB (33.1%)**     | 5.53 MiB (43.6%) |
| [c0ffee](https://github.com/Crypt-0n/C0-FF-EE) (121 rules, 5290 strings)                             | 171 MiB      | 14.2 MiB (8.3%)        | **11.4 MiB (6.69%)**    | 558 MiB (327%)   |
| [icewater](https://github.com/SupportIntelligence/Icewater) (16431 rules, 13155 strings)             | **54.0 MiB** | 77.0 MiB (142%)        | 71.9 MiB (133%)         | 68.2 MiB (126%)  |
| [signature-base](https://github.com/Neo23x0/signature-base) (4297 rules, 23630 strings)              | **30.7 MiB** | 103 MiB (336%)         | 78.1 MiB (254%)         | 31.6 MiB (103%)  |

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
