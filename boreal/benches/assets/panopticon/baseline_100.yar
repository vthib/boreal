
rule baseline_PowerShell_Case_Anomaly {
   meta:
      description = "Detects obfuscated PowerShell hacktools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/danielhbohannon/status/905096106924761088"
      date = "2017-08-11"
      score = 70
   strings:
      // first detect 'powershell' keyword case insensitive
      $s1 = "powershell" fullword nocase ascii wide
      // define the normal cases
      $sr1 = /(powershell|Powershell|PowerShell|POWERSHELL|powerShell)/ fullword ascii wide
      // define the normal cases
      $sn1 = "powershell" fullword ascii wide
      $sn2 = "Powershell" fullword ascii wide
      $sn3 = "PowerShell" fullword ascii wide
      $sn4 = "POWERSHELL" fullword ascii wide
      $sn5 = "powerShell" fullword ascii wide

      // PowerShell with \x19\x00\x00
      $a1 = "wershell -e " nocase wide ascii
      // expected casing
      $an1 = "wershell -e " wide ascii
      $an2 = "werShell -e " wide ascii

      // adding a keyword with a sufficent length and relevancy
      $k1 = "-noprofile" fullword nocase ascii wide
      // define normal cases
      $kn1 = "-noprofile" ascii wide
      $kn2 = "-NoProfile" ascii wide
      $kn3 = "-noProfile" ascii wide
      $kn4 = "-NOPROFILE" ascii wide
      $kn5 = "-Noprofile" ascii wide

      $fp1 = "Microsoft Code Signing" ascii fullword
      $fp2 = "Microsoft Corporation" ascii
   condition:
      filesize < 800KB and (
         // find all 'powershell' occurances and ignore the expected cases
         ( #s1 < 3 and #sr1 > 0 and #s1 > #sr1 ) or
         ( $s1 and not 1 of ($sn*) ) or
         ( $a1 and not 1 of ($an*) ) or
         // find all '-norpofile' occurances and ignore the expected cases
         ( $k1 and not 1 of ($kn*) )
      ) and not 1 of ($fp*)
}

rule baseline_WScriptShell_Case_Anomaly {
   meta:
      description = "Detects obfuscated wscript.shell commands"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-11"
      score = 60
   strings:
      // first detect powershell keyword case insensitive
      $s1 = "WScript.Shell\").Run" nocase ascii wide
      // define the normal cases
      $sn1 = "WScript.Shell\").Run" ascii wide
      $sn2 = "wscript.shell\").run" ascii wide
      $sn3 = "WSCRIPT.SHELL\").RUN" ascii wide
      $sn4 = "Wscript.Shell\").Run" ascii wide
      $sn5 = "WScript.Shell\").Run" ascii wide
      $sn6 = "WScript.shell\").Run" ascii wide
   condition:
      filesize < 800KB and
      ( $s1 and not 1 of ($sn*) )
}

rule baseline_SUSP_BAT_Aux_Jan20_1 {
   meta:
      description = "Detects BAT file often dropped to cleanup temp dirs during infection"
      author = "Florian Roth"
      reference = "https://medium.com/@quoscient/the-chicken-keeps-laying-new-eggs-uncovering-new-gc-maas-tools-used-by-top-tier-threat-actors-531d80a6b4e9"
      date = "2020-01-29"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      score = 65
      hash1 = "f5d558ec505b635b1e37557350562ad6f79b3da5cf2cf74db6e6e648b7a47127"
   strings:
      $s1 = "if exist \"C:\\Users\\" ascii
      $s2 = "\\AppData\\Local\\Temp\\" ascii
      $s3 = "del \"C:\\Users\\" ascii
      $s4 = ".bat\"" ascii
      $s5 = ".exe\" goto" ascii
   condition:
      uint8(0) == 0x3a and filesize <= 1KB and all of them
}

rule baseline_MAL_Trickbot_Oct19_1 {
   meta:
      description = "Detects Trickbot malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-10-02"
      hash1 = "58852140a2dc30e799b7d50519c56e2fd3bb506691918dbf5d4244cc1f4558a2"
      hash2 = "aabf54eb27de3d72078bbe8d99a92f5bcc1e43ff86774eb5321ed25fba5d27d4"
      hash3 = "9d6e4ad7f84d025bbe9f95e74542e7d9f79e054f6dcd7b37296f01e7edd2abae"
   strings:
      $s1 = "Celestor@hotmail.com" fullword ascii
      $s2 = "\\txtPassword" fullword ascii
      $s14 = "Invalid Password, try again!" fullword wide

      $op1 = { 78 c4 40 00 ff ff ff ff b4 47 41 }
      $op2 = { 9b 68 b2 34 46 00 eb 14 8d 55 e4 8d 45 e8 52 50 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 2000KB and 3 of them
}


rule baseline_MAL_Nitol_Malware_Jan19_1 {
   meta:
      description = "Detects Nitol Malware"
      author = "Florian Roth"
      reference = "https://twitter.com/shotgunner101/status/1084602413691166721"
      date = "2019-01-14"
      hash1 = "fe65f6a79528802cb61effc064476f7b48233fb0f245ddb7de5b7cc8bb45362e"
   strings:
      $xc1 = { 00 25 75 20 25 73 00 00 00 30 2E 30 2E 30 2E 30
               00 25 75 20 4D 42 00 00 00 25 64 2A 25 75 25 73
               00 7E 4D 48 7A }
      $xc2 = "GET ^&&%$%$^" ascii

      $n1 = ".htmGET " ascii

      $s1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
      $s2 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
      $s3 = "User-Agent:Mozilla/5.0 (X11; U; Linux i686; en-US; re:1.4.0) Gecko/20080808 Firefox/%d.0" fullword ascii
      $s4 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         1 of ($x*) or
         #n1 > 4 or
         4 of them
      )
}

rule baseline_MAL_RANSOM_RobinHood_May19_1 {
   meta:
      description = "Detects RobinHood Ransomware"
      author = "Florian Roth"
      reference = "https://twitter.com/BThurstonCPTECH/status/1128489465327030277"
      date = "2019-05-15"
      hash1 = "21cb84fc7b33e8e31364ff0e58b078db8f47494a239dc3ccbea8017ff60807e3"
   strings:
      $s1 = ".enc_robbinhood" ascii
      $s2 = "c:\\windows\\temp\\pub.key" ascii fullword
      $s3 = "cmd.exe /c net use * /DELETE /Y" ascii
      $s4 = "sc.exe stop SQLAgent$SQLEXPRESS" nocase
      $s5 = "main.EnableShadowFucks" nocase
      $s6 = "main.EnableRecoveryFCK" nocase
      $s7 = "main.EnableLogLaunders" nocase
      $s8 = "main.EnableServiceFuck" nocase
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}

rule baseline_PoS_Malware_MalumPOS
{
    meta:
        author = "Trend Micro, Inc."
        date = "2015-05-25"
        description = "Used to detect MalumPOS memory dumper"
        sample_filtype = "exe"
    strings:
        $string1 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $string2 = "B)[0-9]{13,19}\\"
        $string3 = "[A-Za-z\\s]{0,30}\\/[A-Za-z\\s]{0,30}\\"
        $string4 = "TRegExpr(exec): ExecNext Without Exec[Pos]"
        $string5 = /Y:\\PROGRAMS\\.{20,300}\.pas/
    condition:
        all of ($string*)
}

rule baseline_APT_Sandworm_Keywords_May20_1 {
   meta:
      description = "Detects commands used by Sandworm group to exploit critical vulernability CVE-2019-10149 in Exim"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
   strings:
      $x1 = "MAIL FROM:<$(run("
      $x2 = "exec\\x20\\x2Fusr\\x2Fbin\\x2Fwget\\x20\\x2DO\\x20\\x2D\\x20http"
   condition:
      filesize < 8000KB and
      1 of them
}

rule baseline_APT_Sandworm_SSH_Key_May20_1 {
   meta:
      description = "Detects SSH key used by Sandworm on exploited machines"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
   strings:
      $x1 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2q/NGN/brzNfJiIp2zswtL33tr74pIAjMeWtXN1p5Hqp5fTp058U1EN4NmgmjX0KzNjjV"
   condition:
      filesize < 1000KB and
      1 of them
}

rule baseline_APT_Sandworm_SSHD_Config_Modification_May20_1 {
   meta:
      description = "Detects ssh config entry inserted by Sandworm on compromised machines"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
      hash1 = "dc074464e50502459038ac127b50b8c68ed52817a61c2f97f0add33447c8f730"
      hash2 = "538d713cb47a6b5ec6a3416404e0fc1ebcbc219a127315529f519f936420c80e"
   strings:     
      $x1 = "AllowUsers mysql_db" ascii

      $a1 = "ListenAddress" ascii fullword
   condition:
      filesize < 10KB and
      all of them
}


rule baseline_SUSP_ZIP_NtdsDIT : T1003_003 {
   meta:
      description = "Detects ntds.dit files in ZIP archives that could be a left over of administrative activity or traces of data exfiltration"
      author = "Florian Roth"
      score = 50
      reference = "https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/"
      date = "2020-08-10"
   strings:
      $s1 = "ntds.dit" ascii 
   condition:
      uint16(0) == 0x4b50 and
      $s1 in (0..256)
}

rule baseline_MAL_BackNet_Nov18_1 {
   meta:
      description = "Detects BackNet samples"
      author = "Florian Roth"
      reference = "https://github.com/valsov/BackNet"
      date = "2018-11-02"
      hash1 = "4ce82644eaa1a00cdb6e2f363743553f2e4bd1eddb8bc84e45eda7c0699d9adc"
   strings:
      $s1 = "ProcessedByFody" fullword ascii
      $s2 = "SELECT * FROM AntivirusProduct" fullword wide
      $s3 = "/C netsh wlan show profile" wide
      $s4 = "browsertornado" fullword wide
      $s5 = "Current user is administrator" fullword wide
      $s6 = "/C choice /C Y /N /D Y /T 4 & Del" wide
      $s7 = "ThisIsMyMutex-2JUY34DE8E23D7" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 2 of them
}

rule baseline_remsec_executable_blob_32 {
   meta:
      copyright = "Symantec"
      description = "Detects malware from Symantec's Strider APT report"
      score = 80
      date = "2016/08/08"
      reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
   strings:
      $code = { 31 06 83 C6 04 D1 E8 73 05 35 01 00 00 D0 E2 F0 }
   condition:
      all of them
}

rule baseline_remsec_executable_blob_64 {
   meta:
      copyright = "Symantec"
      description = "Detects malware from Symantec's Strider APT report"
      score = 80
      date = "2016/08/08"
      reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
   strings:
      $code = { 31 06 48 83 C6 04 D1 E8 73 05 35 01 00 00 D0 E2 EF }
   condition:
      all of them
}

rule baseline_remsec_executable_blob_parser {
   meta:
      copyright = "Symantec"
      description = "Detects malware from Symantec's Strider APT report"
      score = 80
      date = "2016/08/08"
      reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
   strings:
      $code = { ( 0F 82 ?? ?? 00 00 | 72 ?? ) ( 80 | 41 80 ) ( 7? | 7C 24 ) 04 02 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) 02 AA 02 C1 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 8B | 41 8B | 44 8B | 45 8B ) ( 4? | 5? | 6? | 7? | ?4 24 | ?C 24 ) 06 }
   condition:
      all of them
}

rule baseline_remsec_encrypted_api {
   meta:
      copyright = "Symantec"
      description = "Detects malware from Symantec's Strider APT report"
      score = 80
      date = "2016/08/08"
      reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
   strings:
      $open_process = { 91 9A 8F B0 9C 90 8D AF 8C 8C 9A FF }
   condition:
      all of them
}


rule baseline_TA17_318A_rc4_stack_key_fallchill {
   meta:
      description = "HiddenCobra FallChill - rc4_stack_key"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
      date = "2017-11-15"
   strings:
      $stack_key = { 0d 06 09 2a ?? ?? ?? ?? 86 48 86 f7 ?? ?? ?? ?? 0d 01 01 01 ?? ?? ?? ?? 05 00 03 82 41 8b c9 41 8b d1 49 8b 40 08 48 ff c2 88 4c 02 ff ff c1 81 f9 00 01 00 00 7c eb }
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $stack_key
}

rule baseline_TA17_318A_success_fail_codes_fallchill {
   meta:
      description = "HiddenCobra FallChill - success_fail_codes"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
      date = "2017-11-15"
   strings:
      $s0 = { 68 7a 34 12 00 }
      $s1 = { ba 7a 34 12 00 }
      $f0 = { 68 5c 34 12 00 }
      $f1 = { ba 5c 34 12 00 }
   condition:
      (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and (($s0 and $f0) or ($s1 and $f1))
}

rule baseline_Backdoor_Naikon_APT_Sample1 {
	meta:
		description = "Detects backdoors related to the Naikon APT"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://goo.gl/7vHyvh"
		date = "2015-05-14"
		hash = "d5716c80cba8554eb79eecfb4aa3d99faf0435a1833ec5ef51f528146c758eba"
		hash = "f5ab8e49c0778fa208baad660fe4fa40fc8a114f5f71614afbd6dcc09625cb96"
	strings:
		$x0 = "GET http://%s:%d/aspxabcdef.asp?%s HTTP/1.1" fullword ascii
		$x1 = "POST http://%s:%d/aspxabcdefg.asp?%s HTTP/1.1" fullword ascii
		$x2 = "greensky27.vicp.net" fullword ascii
		$x3 = "\\tempvxd.vxd.dll" fullword wide
		$x4 = "otna.vicp.net" fullword ascii
		$x5 = "smithking19.gicp.net" fullword ascii
		
		$s1 = "User-Agent: webclient" fullword ascii
		$s2 = "\\User.ini" fullword ascii
		$s3 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/200" ascii
		$s4 = "\\UserProfile.dll" fullword wide
		$s5 = "Connection:Keep-Alive: %d" fullword ascii
		$s6 = "Referer: http://%s:%d/" fullword ascii
		$s7 = "%s %s %s %d %d %d " fullword ascii
		$s8 = "%s--%s" fullword wide
		$s9 = "Run File Success!" fullword wide
		$s10 = "DRIVE_REMOTE" fullword wide
		$s11 = "ProxyEnable" fullword wide
		$s12 = "\\cmd.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and
		(
			1 of ($x*) or 7 of ($s*)
		)
}


rule baseline_Trojan_Win32_Plainst2 : Platinum
{
	meta:
		author = "Microsoft"
		description = "Zc tool"
		original_sample_sha1 = "3f2ce812c38ff5ac3d813394291a5867e2cddcf2"
		unpacked_sample_sha1 = "88ff852b1b8077ad5a19cc438afb2402462fbd1a"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"

	strings:
		$str1 = "Connected [%s:%d]..."
		$str2 = "reuse possible: %c"
		$str3 = "] => %d%%\x0a"

	condition:
		$str1 and $str2 and $str3
}

rule baseline_Trojan_Win32_Plakpeer : Platinum
{
	meta:
		author = "Microsoft"
		description = "Zc tool v2"
		original_sample_sha1 = "2155c20483528377b5e3fde004bb604198463d29"
		unpacked_sample_sha1 = "dc991ef598825daabd9e70bac92c79154363bab2"
		activity_group = "Platinum"
		version = "1.0"
		last_modified = "2016-04-12"

	strings:
		$str1 = "@@E0020(%d)" wide
		$str2 = /exit.{0,3}@exit.{0,3}new.{0,3}query.{0,3}rcz.{0,3}scz/ wide
		$str3 = "---###---" wide
		$str4 = "---@@@---" wide

	condition:
		$str1 and $str2 and $str3 and $str4
}

rule baseline_HttpBrowser_RAT_dropper_Gen1 {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Dropper"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "808de72f1eae29e3c1b2c32be1b84c5064865a235866edf5e790d2a7ba709907"
		hash2 = "f6f966d605c5e79de462a65df437ddfca0ad4eb5faba94fc875aba51a4b894a7"
		hash3 = "f424965a35477d822bbadb821125995616dc980d3d4f94a68c87d0cd9b291df9"
		hash4 = "01441546fbd20487cb2525a0e34e635eff2abe5c3afc131c7182113220f02753"
		hash5 = "8cd8159f6e4689f572e2087394452e80e62297af02ca55fe221fe5d7570ad47b"
		hash6 = "10de38419c9a02b80ab7bf2f1f1f15f57dbb0fbc9df14b9171dc93879c5a0c53"
		hash7 = "c2fa67e970d00279cec341f71577953d49e10fe497dae4f298c2e9abdd3a48cc"
	strings:
		$x1 = "1001=cmd.exe" fullword ascii 
		$x2 = "1003=ShellExecuteA" fullword ascii 
		$x3 = "1002=/c del /q %s" fullword ascii
		$x4 = "1004=SetThreadPriority" fullword ascii

		/* $s1 = "pnipcn.dllUT" fullword ascii
		$s2 = "ssonsvr.exeUT" fullword ascii
		$s3 = "navlu.dllUT" fullword ascii
		$s4 = "@CONOUT$" fullword wide 
		$s5 = "VPDN_LU.exeUT" fullword ascii
		$s6 = "msi.dll.urlUT" fullword ascii
		$s7 = "setup.exeUT" fullword ascii 
		$s8 = "pnipcn.dll.urlUT" fullword ascii
		$s9 = "ldvpreg.exeUT" fullword ascii */

		$op0 = { e8 71 11 00 00 83 c4 10 ff 4d e4 8b f0 78 07 8b } /* Opcode */
		$op1 = { e8 85 34 00 00 59 59 8b 86 b4 } /* Opcode */
		$op2 = { 8b 45 0c 83 38 00 0f 84 97 } /* Opcode */
		$op3 = { 8b 45 0c 83 38 00 0f 84 98 } /* Opcode */
		$op4 = { 89 7e 0c ff 15 a0 50 40 00 59 8b d8 6a 20 59 8d } /* Opcode */
		$op5 = { 56 8d 85 cd fc ff ff 53 50 88 9d cc fc ff ff e8 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of ($x*) and 1 of ($op*)
}

rule baseline_HttpBrowser_RAT_Sample1 {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample update.hancominc.com"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 80
		hash1 = "be334d1f8fa65a723af65200a166c2bbdb06690c8b30fafe772600e4662fc68b"
		hash2 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
	strings:
		$s0 = "update.hancominc.com" fullword wide 
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and $s0
}

rule baseline_HttpBrowser_RAT_Sample2 {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Sample"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 80
		hash1 = "c57c5a2c322af2835ae136b75283eaaeeaa6aa911340470182a9983ae47b8992"
	strings:
		$s0 = "nKERNEL32.DLL" fullword wide
		$s1 = "WUSER32.DLL" fullword wide
		$s2 = "mscoree.dll" fullword wide
		$s3 = "VPDN_LU.exeUT" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule baseline_HttpBrowser_RAT_Gen {
	meta:
		description = "Threat Group 3390 APT Sample - HttpBrowser RAT Generic"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 90
		hash1 = "0299493ccb175d452866f5e21d023d3e92cd8d28452517d1d19c0f05f2c5ca27"
		hash2 = "065d055a90da59b4bdc88b97e537d6489602cb5dc894c5c16aff94d05c09abc7"
		hash3 = "05c7291db880f94c675eea336ecd66338bd0b1d49ad239cc17f9df08106e6684"
		hash4 = "07133f291fe022cd14346cd1f0a649aa2704ec9ccadfab809ca9c48b91a7d81b"
		hash5 = "0f8893e87ddec3d98e39a57f7cd530c28e36d596ea0a1d9d1e993dc2cae0a64d"
		hash6 = "108e6633744da6efe773eb78bd0ac804920add81c3dde4b26e953056ac1b26c5"
		hash7 = "1052ad7f4d49542e4da07fa8ea59c15c40bc09a4d726fad023daafdf05866ebb"
		hash8 = "1277ede988438d4168bb5b135135dd3b9ae7d9badcdf1421132ca4692dd18386"
		hash9 = "19be90c152f7a174835fd05a0b6f722e29c648969579ed7587ae036679e66a7b"
		hash10 = "1e7133bf5a9fe5e462321aafc2b7770b8e4183a66c7fef14364a0c3f698a29af"
		hash11 = "2264e5e8fcbdcb29027798b200939ecd8d1d3ad1ef0aef2b8ce7687103a3c113"
		hash12 = "2a1bdeb0a021fb0bdbb328bd4b65167d1f954c871fc33359cb5ea472bad6e13e"
		hash13 = "259a2e0508832d0cf3f4f5d9e9e1adde17102d2804541a9587a9a4b6f6f86669"
		hash14 = "240d9ce148091e72d8f501dbfbc7963997d5c2e881b4da59a62975ddcbb77ca2"
		hash15 = "211a1b195cf2cc70a2caf8f1aafb8426eb0e4bae955e85266490b12b5322aa16"
		hash16 = "2d25c6868c16085c77c58829d538b8f3dbec67485f79a059f24e0dce1e804438"
		hash17 = "2d932d764dd9b91166361d8c023d64a4480b5b587a6087b0ce3d2ac92ead8a7d"
		hash18 = "3556722d9aa37beadfa6ba248a66576f767e04b09b239d3fb0479fa93e0ba3fd"
		hash19 = "365e1d4180e93d7b87ba28ce4369312cbae191151ac23ff4a35f45440cb9be48"
		hash20 = "36c49f18ce3c205152eef82887eb3070e9b111d35a42b534b2fb2ee535b543c0"
		hash21 = "3eeb1fd1f0d8ab33f34183893c7346ddbbf3c19b94ba3602d377fa2e84aaad81"
		hash22 = "3fa8d13b337671323e7fe8b882763ec29b6786c528fa37da773d95a057a69d9a"
	strings:
		$s0 = "%d|%s|%04d/%02d/%02d %02d:%02d:%02d|%ld|%d" fullword wide 
		$s1 = "HttpBrowser/1.0" fullword wide
		$s2 = "set cmd : %s" ascii fullword
		$s3 = "\\config.ini" wide fullword
	condition:
		uint16(0) == 0x5a4d and filesize < 45KB and filesize > 20KB and all of them
}

rule baseline_PlugX_NvSmartMax_Gen {
	meta:
		description = "Threat Group 3390 APT Sample - PlugX NvSmartMax Generic"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://snip.ly/giNB"
		date = "2015-08-06"
		score = 70
		hash1 = "718fc72942b9b706488575c0296017971170463f6f40fa19b08fc84b79bf0cef"
		hash2 = "1c0379481d17fc80b3330f148f1b87ff613cfd2a6601d97920a0bcd808c718d0"
		hash3 = "555952aa5bcca4fa5ad5a7269fece99b1a04816d104ecd8aefabaa1435f65fa5"
		hash4 = "71f7a9da99b5e3c9520bc2cc73e520598d469be6539b3c243fb435fe02e44338"
		hash5 = "65bbf0bd8c6e1ccdb60cf646d7084e1452cb111d97d21d6e8117b1944f3dc71e"
	strings:
		$s0 = "NvSmartMax.dll" fullword ascii
		$s1 = "NvSmartMax.dll.url" fullword ascii
		$s2 = "Nv.exe" fullword ascii
		$s4 = "CryptProtectMemory failed" fullword ascii 
		$s5 = "CryptUnprotectMemory failed" fullword ascii 
		$s7 = "r%.*s(%d)%s" fullword wide
		$s8 = " %s CRC " fullword wide

		$op0 = { c6 05 26 49 42 00 01 eb 4a 8d 85 00 f8 ff ff 50 } /* Opcode */
		$op1 = { 8d 85 c8 fe ff ff 50 8d 45 c8 50 c6 45 47 00 e8 } /* Opcode */
		$op2 = { e8 e6 65 00 00 50 68 10 43 41 00 e8 56 84 00 00 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and all of ($s*) and 1 of ($op*)
}


rule baseline_UACElevator {
	meta:
		description = "UACElevator bypassing UAC - file UACElevator.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/MalwareTech/UACElevator"
		date = "2015-05-14"
		hash = "fd29d5a72d7a85b7e9565ed92b4d7a3884defba6"
	strings:
		$x1 = "\\UACElevator.pdb" ascii

		$s1 = "%userprofile%\\Downloads\\dwmapi.dll" fullword ascii
		$s2 = "%windir%\\system32\\dwmapi.dll" fullword ascii
		$s3 = "Infection module: %s" fullword ascii
		$s4 = "Could not save module to %s" fullword ascii
		$s5 = "%s%s%p%s%ld%s%d%s" fullword ascii
		$s6 = "Stack area around _alloca memory reserved by this function is corrupted" fullword ascii
		$s7 = "Stack around the variable '" fullword ascii
		$s8 = "MSVCR120D.dll" fullword wide
		$s9 = "Address: 0x" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 172KB and
			( $x1 or 8 of ($s*) )
}

rule baseline_s4u {
	meta:
		description = "Detects s4u executable which allows the creation of a cmd.exe with the context of any user without requiring the password. - file s4u.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/aurel26/s-4-u-for-windows"
		date = "2015-06-05"
		hash = "cfc18f3d5306df208461459a8e667d89ce44ed77"
		score = 50
	strings:
		// Specific strings (may change)
		$x0 = "s4u.exe Domain\\Username [Extra SID]" fullword ascii
		$x1 = "\\Release\\s4u.pdb" ascii

		// Less specific strings
		$s0 = "CreateProcessAsUser failed (error %u)." fullword ascii
		$s1 = "GetTokenInformation failed (error: %u)." fullword ascii
		$s2 = "LsaLogonUser failed (error 0x%x)." fullword ascii
		$s3 = "LsaLogonUser: OK, LogonId: 0x%x-0x%x" fullword ascii
		$s4 = "LookupPrivilegeValue failed (error: %u)." fullword ascii
		$s5 = "The token does not have the specified privilege (%S)." fullword ascii
		$s6 = "Unable to parse command line." fullword ascii
		$s7 = "Unable to find logon SID." fullword ascii
		$s8 = "AdjustTokenPrivileges failed (error: %u)." fullword ascii
		$s9 = "AdjustTokenPrivileges (%S): OK" fullword ascii

		// Generic
		$g1 = "%systemroot%\\system32\\cmd.exe" wide
		$g2 = "SeTcbPrivilege" wide
		$g3 = "winsta0\\default" wide
		$g4 = ".rsrc"
		$g5 = "HeapAlloc"
		$g6 = "GetCurrentProcess"
		$g7 = "HeapFree"
		$g8 = "GetProcessHeap"
		$g9 = "ExpandEnvironmentStrings"
		$g10 = "ConvertStringSidToSid"
		$g11 = "LookupPrivilegeValue"
		$g12 = "AllocateLocallyUniqueId"
		$g13 = "ADVAPI32.dll"
		$g14 = "LsaLookupAuthenticationPackage"
		$g15 = "Secur32.dll"
		$g16 = "MSVCR120.dll"

	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and ( 1 of ($x*) or all of ($s*) or all of ($g*) )
}

rule baseline_gen_python_reverse_shell
{
   meta:
      description = "Python Base64 encoded reverse shell"
      author = "John Lambert @JohnLaTwC"
      reference = "https://www.virustotal.com/en/file/9ec5102bcbabc45f2aa7775464f33019cfbe9d766b1332ee675957c923a17efd/analysis/"
      date = "2018-02-24"
      hash1 = "9ec5102bcbabc45f2aa7775464f33019cfbe9d766b1332ee675957c923a17efd"
      hash2 = "bfb5c622a3352bb71b86df81c45ccefaa68b9f7cc0a3577e8013aad951308f12"
   strings:
      $h1 = "import base64" fullword ascii

      $s1 = "b64decode" fullword ascii
      $s2 = "lambda" fullword ascii
      $s3 = "version_info" fullword ascii

      //Base64 encoded versions of these strings
      // socket.SOCK_STREAM
      $enc_x0 = /(AG8AYwBrAGUAdAAuAFMATwBDAEsAXwBTAFQAUgBFAEEATQ|b2NrZXQuU09DS19TVFJFQU|c29ja2V0LlNPQ0tfU1RSRUFN|cwBvAGMAawBlAHQALgBTAE8AQwBLAF8AUwBUAFIARQBBAE0A|MAbwBjAGsAZQB0AC4AUwBPAEMASwBfAFMAVABSAEUAQQBNA|NvY2tldC5TT0NLX1NUUkVBT)/ ascii

      //.connect((
      $enc_x1 = /(4AYwBvAG4AbgBlAGMAdAAoACgA|5jb25uZWN0KC|AGMAbwBuAG4AZQBjAHQAKAAoA|LgBjAG8AbgBuAGUAYwB0ACgAKA|LmNvbm5lY3QoK|Y29ubmVjdCgo)/

      //time.sleep
      $enc_x2 = /(AGkAbQBlAC4AcwBsAGUAZQBwA|aW1lLnNsZWVw|dABpAG0AZQAuAHMAbABlAGUAcA|dGltZS5zbGVlc|QAaQBtAGUALgBzAGwAZQBlAHAA|RpbWUuc2xlZX)/

      //.recv
      $enc_x3 = /(4AcgBlAGMAdg|5yZWN2|AHIAZQBjAHYA|cmVjd|LgByAGUAYwB2A|LnJlY3)/
   condition:
      uint32be(0) == 0x696d706f
      and $h1 at 0
      and filesize < 40KB
      and all of ($s*)
      and all of ($enc_x*)
}


rule baseline_PrikormkaModule
{
    strings:
        // binary
        $str1 = {6D 70 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
        $str2 = {68 6C 70 75 63 74 66 2E 64 6C 6C 00 43 79 63 6C 65}
        $str3 = {00 6B 6C 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67 00}
        $str4 = {69 6F 6D 75 73 2E 64 6C 6C 00 53 74 61 72 74 69 6E 67}
        $str5 = {61 74 69 6D 6C 2E 64 6C 6C 00 4B 69 63 6B 49 6E 50 6F 69 6E 74}
        $str6 = {73 6E 6D 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}
        $str7 = {73 63 72 73 68 2E 64 6C 6C 00 47 65 74 52 65 61 64 79 46 6F 72 44 65 61 64}

        // encrypted
        $str8 = {50 52 55 5C 17 51 58 17 5E 4A}
        $str9 = {60 4A 55 55 4E 53 58 4B 17 52 57 17 5E 4A}
        $str10 = {55 52 5D 4E 5B 4A 5D 17 51 58 17 5E 4A}
        $str11 = {60 4A 55 55 4E 61 17 51 58 17 5E 4A}
        $str12 = {39 5D 17 1D 1C 0A 3C 57 59 3B 1C 1E 57 58 4C 54 0F}

        // mutex
        $str13 = "ZxWinDeffContex" ascii wide
        $str14 = "Paramore756Contex43" wide
        $str15 = "Zw_&one@ldrContext43" wide

        // other
        $str16 = "A95BL765MNG2GPRS"

        // dll names
        $str17 = "helpldr.dll" wide fullword
        $str18 = "swma.dll" wide fullword
        $str19 = "iomus.dll" wide fullword
        $str20 = "atiml.dll"  wide fullword
        $str21 = "hlpuctf.dll" wide fullword
        $str22 = "hauthuid.dll" ascii wide fullword

        // rbcon
        $str23 = "[roboconid][%s]" ascii fullword
        $str24 = "[objectset][%s]" ascii fullword
        $str25 = "rbcon.ini" wide fullword

        // files and logs
        $str26 = "%s%02d.%02d.%02d_%02d.%02d.%02d.skw" ascii fullword
        $str27 = "%02d.%02d.%02d_%02d.%02d.%02d.%02d.rem" wide fullword

        // pdb strings
        $str28 = ":\\!PROJECTS!\\Mina\\2015\\" ascii
        $str29 = "\\PZZ\\RMO\\" ascii
        $str30 = ":\\work\\PZZ" ascii
        $str31 = "C:\\Users\\mlk\\" ascii
        $str32 = ":\\W o r k S p a c e\\" ascii
        $str33 = "D:\\My\\Projects_All\\2015\\" ascii
        $str34 = "\\TOOLS PZZ\\Bezzahod\\" ascii

    condition:
        uint16(0) == 0x5a4d and (any of ($str*))
}

rule baseline_PrikormkaEarlyVersion
{
    strings:
        $str1 = "IntelRestore" ascii fullword
        $str2 = "Resent" wide fullword
        $str3 = "ocp8.1" wide fullword
        $str4 = "rsfvxd.dat" ascii fullword
        $str5 = "tsb386.dat" ascii fullword
        $str6 = "frmmlg.dat" ascii fullword
        $str7 = "smdhost.dll" ascii fullword
        $str8 = "KDLLCFX" wide fullword
        $str9 = "KDLLRUNDRV" wide fullword
    condition:
        uint16(0) == 0x5a4d and (2 of ($str*))
}


rule baseline_SUSP_MalDoc_ExcelMacro {
  meta:
    description = "Detects malicious Excel macro Artifacts"
    author = "James Quinn"
    date = "2020-11-03"
    reference = "YARA Exchange - Undisclosed Macro Builder"
  strings:
    $artifact1 = {5c 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2e 00 ?? 00 ?? 00}
    $url1 = "http://" wide
    $url2 = "https://" wide
    $import1 = "URLDownloadToFileA" wide ascii
    $macro = "xl/macrosheets/"
  condition:
    uint16(0) == 0x4b50 and
    filesize < 2000KB and
    $artifact1 and $macro and $import1 and 1 of ($url*)
}

rule baseline_plist_macos {
    meta:
        hashes = "76eb97aba93979be06dbf0a872518f9514d0bb20b680c887d6fd5cc79dce3681"
    strings:
        $sr1 = "PropertyList-1.0.dtd" fullword
        $sr2 = "<plist"
    condition:
        filesize < 20KB
        and uint32be(0) == 0x3c3f786d
        and all of ($sr*)
        and @sr2[1] < 0x100

}

rule baseline_gen_malware_MacOS_plist_suspicious {
   meta:
      description = "Suspicious PLIST files in MacOS (possible malware persistence)"
      author = "John Lambert @JohnLaTwC"
      date = "2018-12-14"
      reference = "https://objective-see.com/blog/blog_0x3A.html"
      hash1 = "0541fc6a11f4226d52ae3d4158deb8f50ed61b25bb5f889d446102e1ee57b76d"
      hash2 = "6cc6abec7d203f99c43ce16630edc39451428d280b02739757f17fd01fc7dca3"
      hash3 = "76eb97aba93979be06dbf0a872518f9514d0bb20b680c887d6fd5cc79dce3681"
      hash4 = "8921e3f1955f7141d1231f8cfd95230143525f259e578fdc1dd98494f62ec4a1"
      hash5 = "9a3fd0d2b0bca7d2f7e3c70cb15a7005a1afa1ce78371fd3fa9c526a288b64ce"
      hash6 = "737355121685afc38854413d8a1657886f9aa24f54673953749386defe843017"
      hash7 = "9b77622653934995ee8bb5562df311f5bb6d6719933e2671fe231a664da76d30"
      hash8 = "c449f8115b4b939271cb92008a497457e1ab1cf2cbd8f4b58f7ba955cf5624f0"
      hash9 = "cdb2fb9c8e84f0140824403ec32a2431fb357cd0f184c1790152834cc3ad3c1b"
   strings:
      $p1 = "python" ascii
      $p2 = "<string>-c" ascii
      // possible bitcoin wallet. could be coinminer config
      $v0 = /\<string\>[\/|\w]{0,20}\+[\/|\+|=|\w]{59,80}\<\/string\>/
      //see 0541fc6a11f4226d52ae3d4158deb8f50ed61b25bb5f889d446102e1ee57b76d
      $v1 = "curl " fullword
      // see 9a3fd0d2b0bca7d2f7e3c70cb15a7005a1afa1ce78371fd3fa9c526a288b64ce
      $v2 = "PAYLOAD_DATA"
      $v3 = "base64"
      // see 9a3fd0d2b0bca7d2f7e3c70cb15a7005a1afa1ce78371fd3fa9c526a288b64ce
      //PAYLOAD_BASE64
      $vb640 = /(AAQQBZAEwATwBBAEQAXwBCAEEAUwBFADYANA|AEEAWQBMAE8AQQBEAF8AQgBBAFMARQA2ADQA|BBWUxPQURfQkFTRTY0|QVlMT0FEX0JBU0U2N|UABBAFkATABPAEEARABfAEIAQQBTAEUANgA0A|UEFZTE9BRF9CQVNFNj)/
      //subprocess
      $vb641 = /(AHUAYgBwAHIAbwBjAGUAcwBzA|c3VicHJvY2Vzc|cwB1AGIAcAByAG8AYwBlAHMAcw|dWJwcm9jZXNz|MAdQBiAHAAcgBvAGMAZQBzAHMA|N1YnByb2Nlc3)/
      // #!/usr
      $vb642 = "IyEvdXNy"
      // # -*-
      $vb643 = "IyAtKi0"
      //add_header
      $vb644 = /(AGQAZABfAGgAZQBhAGQAZQByA|EAZABkAF8AaABlAGEAZABlAHIA|FkZF9oZWFkZX|YQBkAGQAXwBoAGUAYQBkAGUAcg|YWRkX2hlYWRlc|ZGRfaGVhZGVy)/

      $fp1 = "&#10;do&#10;&#09;echo"  // Shells.plist
      $fp2 = "<string>com.cisco.base64</string>"  // Webex
      $fp3 = "video/mp4;base64"
      $fp4 = "<key>Content-Length</key>"
   condition:
      baseline_plist_macos and ( 1 of ($v*) or all of ($p*) )
      and not 1 of ($fp*)
}


rule baseline_APT_HackTool_MSIL_GPOHUNT_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'gpohunt' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "751a9270-2de0-4c81-9e29-872cd6378303" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule baseline_APT_HackTool_MSIL_JUSTASK_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'justask' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "aa59be52-7845-4fed-9ea5-1ea49085d67a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule baseline_APT_Trojan_Win_REDFLARE_4
{
    meta:
        date = "2020-12-01"
        modified = "2020-12-01"
        md5 = "a8b5dcfea5e87bf0e95176daa243943d, 9dcb6424662941d746576e62712220aa"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = "LogonUserW" fullword
        $s2 = "ImpersonateLoggedOnUser" fullword
        $s3 = "runCommand" fullword
        $user_logon = { 22 02 00 00 [1-10] 02 02 00 00 [0-4] E8 [4-40] ( 09 00 00 00 [1-10] 03 00 00 00 | 6A 03 6A 09 ) [4-30] FF 15 [4] 85 C0 7? }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule baseline_APT_HackTool_MSIL_TITOSPECIAL_1
{
    meta:
        date = "2020-11-25"
        modified = "2020-11-25"
        md5 = "4bf96a7040a683bd34c618431e571e26"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $ind_dump = { 1F 10 16 28 [2] 00 0A 6F [2] 00 0A [50-200] 18 19 18 73 [2] 00 0A 13 [1-4] 06 07 11 ?? 6F [2] 00 0A 18 7E [2] 00 0A 7E [2] 00 0A 7E [2] 00 0A 28 [2] 00 06 }
        $ind_s1 = "NtReadVirtualMemory" fullword wide
        $ind_s2 = "WriteProcessMemory" fullword
        $shellcode_x64 = { 4C 8B D1 B8 3C 00 00 00 0F 05 C3 }
        $shellcode_x86 = { B8 3C 00 00 00 33 C9 8D 54 24 04 64 FF 15 C0 00 00 00 83 C4 04 C2 14 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($ind*) and any of ($shellcode* )
}

rule baseline_Dropper_LNK_LNKSmasher_1
{
    meta:
        description = "The LNKSmasher project contains a prebuilt LNK file that has pieces added based on various configuration items. Because of this, several artifacts are present in every single LNK file generated by LNKSmasher, including the Drive Serial #, the File Droid GUID, and the GUID CLSID."
        md5 = "0a86d64c3b25aa45428e94b6e0be3e08"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $drive_serial = { 12 F7 26 BE }
        $file_droid_guid = { BC 96 28 4F 0A 46 54 42 81 B8 9F 48 64 D7 E9 A5 }
        $guid_clsid = { E0 4F D0 20 EA 3A 69 10 A2 D8 08 00 2B 30 30 9D }
        $header = { 4C 00 00 00 01 14 02 }
    condition:
        $header at 0 and all of them
}

rule baseline_CredTheft_MSIL_TitoSpecial_1
{
    meta:
        description = "This rule looks for .NET PE files that have the strings of various method names in the TitoSpecial code."
        md5 = "4bf96a7040a683bd34c618431e571e26"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $str1 = "Minidump" ascii wide
        $str2 = "dumpType" ascii wide
        $str3 = "WriteProcessMemory" ascii wide
        $str4 = "bInheritHandle" ascii wide
        $str5 = "GetProcessById" ascii wide
        $str6 = "SafeHandle" ascii wide
        $str7 = "BeginInvoke" ascii wide
        $str8 = "EndInvoke" ascii wide
        $str9 = "ConsoleApplication1" ascii wide
        $str10 = "getOSInfo" ascii wide
        $str11 = "OpenProcess" ascii wide
        $str12 = "LoadLibrary" ascii wide
        $str13 = "GetProcAddress" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of ($str*)
}

rule baseline_Builder_MSIL_G2JS_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the Gadget2JScript project."
        md5 = "fa255fdc88ab656ad9bc383f9b322a76"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "AF9C62A1-F8D2-4BE0-B019-0A7873E81EA9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}

rule baseline_APT_Loader_Win32_DShell_2
{
    meta:
        date = "2020-11-27"
        modified = "2020-11-27"
        md5 = "590d98bb74879b52b97d8a158af912af"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $sb1 = { 6A 40 68 00 30 00 00 [4-32] E8 [4-8] 50 [0-16] E8 [4-150] 6A FF [1-32] 6A 00 6A 00 5? 6A 00 6A 00 [0-32] E8 [4] 50 }
        $ss1 = "\x00CreateThread\x00"
        $ss2 = "base64.d" fullword
        $ss3 = "core.sys.windows" fullword
        $ss4 = "C:\\Users\\config.ini" fullword
        $ss5 = "Invalid config file" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x010B) and all of them
}


rule baseline_CredTheft_Win_EXCAVATOR_2
{
    meta:
        description = "This rule looks for the binary signature of the routine that calls PssFreeSnapshot found in the Excavator-Reflector DLL."
        md5 = "6a9a114928554c26675884eeb40cc01b"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $bytes1 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A0 01 00 00 48 8B 05 4C 4A 01 00 48 33 C4 48 89 85 90 00 00 00 BA 50 00 00 00 C7 05 CB 65 01 00 43 00 3A 00 66 89 15 EC 65 01 00 4C 8D 44 24 68 48 8D 15 D8 68 01 00 C7 05 B2 65 01 00 5C 00 57 00 33 C9 C7 05 AA 65 01 00 69 00 6E 00 C7 05 A4 65 01 00 64 00 6F 00 C7 05 9E 65 01 00 77 00 73 00 C7 05 98 65 01 00 5C 00 4D 00 C7 05 92 65 01 00 45 00 4D 00 C7 05 8C 65 01 00 4F 00 52 00 C7 05 86 65 01 00 59 00 2E 00 C7 05 80 65 01 00 44 00 4D 00 C7 05 72 68 01 00 53 00 65 00 C7 05 6C 68 01 00 44 00 65 00 C7 05 66 68 01 00 42 00 75 00 C7 05 60 68 01 00 47 00 50 00 C7 05 5A 68 01 00 72 00 69 00 C7 05 54 68 01 00 56 00 69 00 C7 05 4E 68 01 00 4C 00 45 00 C7 05 48 68 01 00 67 00 65 00 C7 05 12 67 01 00 6C 73 61 73 C7 05 0C 67 01 00 73 2E 65 78 C6 05 09 67 01 00 65 FF 15 63 B9 00 00 45 33 F6 85 C0 74 66 48 8B 44 24 68 48 89 44 24 74 C7 44 24 70 01 00 00 00 C7 44 24 7C 02 00 00 00 FF 15 A4 B9 00 00 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF 15 1A B9 00 00 85 C0 74 30 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF 15 EF B8 00 00 FF 15 11 B9 00 00 48 8B 4C 24 48 FF 15 16 B9 00 00 48 89 9C 24 B0 01 00 00 48 8D 0D BF 2E 01 00 48 89 B4 24 B8 01 00 00 4C 89 74 24 40 FF 15 1C B9 00 00 48 85 C0 0F 84 B0 00 00 00 48 8D 15 AC 2E 01 00 48 8B C8 FF 15 1B B9 00 00 48 8B D8 48 85 C0 0F 84 94 00 00 00 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 06 15 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 63 66 0F 1F 44 00 00 48 8B 4C 24 40 4C 8D 45 80 41 B9 04 01 00 00 33 D2 FF 15 89 B8 00 00 48 8D 15 F2 65 01 00 48 8D 4D 80 E8 49 0F 00 00 48 85 C0 75 38 33 D2 48 8D 4D 80 41 B8 04 01 00 00 E8 A3 14 00 00 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 A3 33 C0 E9 F5 00 00 00 48 8B 5C 24 40 48 8B CB FF 15 5E B8 00 00 8B F0 48 85 DB 74 E4 85 C0 74 E0 4C 8D 4C 24 50 48 89 BC 24 C0 01 00 00 BA FD 03 00 AC 41 B8 1F 00 10 00 48 8B CB FF 15 12 B8 00 00 85 C0 0F 85 A0 00 00 00 48 8D 05 43 FD FF FF 4C 89 74 24 30 C7 44 24 28 80 00 00 00 48 8D 0D 3F 63 01 00 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 20 01 00 00 00 BA 00 00 00 10 4C 89 74 24 60 FF 15 E4 B7 00 00 48 8B F8 48 83 F8 FF 74 59 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 00 00 00 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF 15 B1 B9 00 00 48 8B CB FF 15 78 B7 00 00 48 8B CF FF 15 6F B7 00 00 FF 15 B1 B7 00 00 48 8B 54 24 50 48 8B C8 FF 15 53 B7 00 00 33 C9 FF 15 63 B7 00 00 CC 48 8B CB FF 15 49 B7 00 00 48 8B BC 24 C0 01 00 00 33 C0 48 8B B4 24 B8 01 00 00 48 8B 9C 24 B0 01 00 00 48 8B 8D 90 00 00 00 48 33 CC E8 28 00 00 00 4C 8B B4 24 C8 01 00 00 48 81 C4 A0 01 00 00 5D C3 }
        $bytes2 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 85 9? ?? ?? ?0 BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 89 ?? ?? ?? ?? ?? 4C 8D 44 24 68 48 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 68 48 89 44 24 74 C7 44 24 7? ?1 ?? ?? ?? C7 44 24 7C 02 ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 4C 24 48 FF ?? ?? ?? ?? ?? 48 89 9C 24 B? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 B4 24 B8 01 ?? ?? 4C 89 74 24 40 FF ?? ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 0F 1F 44 ?? ?? 48 8B 4C 24 40 4C 8D 45 80 41 ?? ?? ?? ?? ?? 33 D2 FF ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8D 4D 80 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 40 48 8B CB FF ?? ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 50 48 89 BC 24 C? ?1 ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 30 C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 2? ?1 ?? ?? ?? BA ?? ?? ?? ?? 4C 89 74 24 60 FF ?? ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 ?? ?? ?? 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 54 24 50 48 8B C8 FF ?? ?? ?? ?? ?? 33 C9 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B BC 24 C? ?1 ?? ?? 33 C0 48 8B B4 24 B8 01 ?? ?? 48 8B 9C 24 B? ?1 ?? ?? 48 8B 8D 9? ?? ?? ?0 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 C8 01 ?? ?? 48 81 C4 A? ?1 ?? ?? 5D C3 }
        $bytes3 = { 4C 89 74 24 20 55 48 8D AC 24 60 FF FF FF 48 81 EC A? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 33 C4 48 89 85 9? ?? ?? ?0 BA ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 89 ?? ?? ?? ?? ?? 4C 8D 44 24 68 48 ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C7 ?? ?? ?? ?? ?? ?? ?? ?? ?? C6 ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 68 48 89 44 24 74 C7 44 24 7? ?1 ?? ?? ?? C7 44 24 7C 02 ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 48 41 8D 56 20 FF ?? ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 48 4C 8D 44 24 70 4C 89 74 24 28 45 33 C9 33 D2 4C 89 74 24 20 FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 4C 24 48 FF ?? ?? ?? ?? ?? 48 89 9C 24 B? ?1 ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 B4 24 B8 01 ?? ?? 4C 89 74 24 40 FF ?? ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8B C8 FF ?? ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 75 ?? 66 0F 1F 44 ?? ?? 48 8B 4C 24 40 4C 8D 45 80 41 ?? ?? ?? ?? ?? 33 D2 FF ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 8D 4D 80 E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D 80 41 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4C 24 40 48 8D 44 24 40 45 33 C9 48 89 44 24 20 45 33 C0 BA ?? ?? ?? ?? FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 40 48 8B CB FF ?? ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 50 48 89 BC 24 C? ?1 ?? ?? BA ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4C 89 74 24 30 C7 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 33 C9 48 89 44 24 58 45 33 C0 C7 44 24 2? ?1 ?? ?? ?? BA ?? ?? ?? ?? 4C 89 74 24 60 FF ?? ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 50 48 8D 44 24 58 48 89 44 24 30 41 B9 02 ?? ?? ?? 4C 89 74 24 28 4C 8B C7 8B D6 4C 89 74 24 20 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B CF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8B 54 24 50 48 8B C8 FF ?? ?? ?? ?? ?? 33 C9 FF ?? ?? ?? ?? ?? 48 8B CB FF ?? ?? ?? ?? ?? 48 8B BC 24 C? ?1 ?? ?? 33 C0 48 8B B4 24 B8 01 ?? ?? 48 8B 9C 24 B? ?1 ?? ?? 48 8B 8D 9? ?? ?? ?0 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 C8 01 ?? ?? 48 81 C4 A? ?1 ?? ?? 5D C3 }
        $bytes4 = { 4C 89 74 24 ?? 55 48 8D AC 24 ?? ?? ?? ?? 48 81 EC A0 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? BA 50 00 00 00 C7 05 ?? ?? ?? ?? 43 00 3A 00 66 89 15 ?? ?? 01 00 4C 8D 44 24 ?? 48 8D 15 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 5C 00 57 00 33 C9 C7 05 ?? ?? ?? ?? 69 00 6E 00 C7 05 ?? ?? ?? ?? 64 00 6F 00 C7 05 ?? ?? ?? ?? 77 00 73 00 C7 05 ?? ?? ?? ?? 5C 00 4D 00 C7 05 ?? ?? ?? ?? 45 00 4D 00 C7 05 ?? ?? ?? ?? 4F 00 52 00 C7 05 ?? ?? ?? ?? 59 00 2E 00 C7 05 ?? ?? ?? ?? 44 00 4D 00 C7 05 ?? ?? ?? ?? 53 00 65 00 C7 05 ?? ?? ?? ?? 44 00 65 00 C7 05 ?? ?? ?? ?? 42 00 75 00 C7 05 ?? ?? ?? ?? 47 00 50 00 C7 05 ?? ?? ?? ?? 72 00 69 00 C7 05 ?? ?? ?? ?? 56 00 69 00 C7 05 ?? ?? ?? ?? 4C 00 45 00 C7 05 ?? ?? ?? ?? 67 00 65 00 C7 05 ?? ?? ?? ?? 6C 73 61 73 C7 05 ?? ?? ?? ?? 73 2E 65 78 C6 05 ?? ?? ?? ?? 65 FF 15 ?? ?? ?? ?? 45 33 F6 85 C0 74 ?? 48 8B 44 24 ?? 48 89 44 24 ?? C7 44 24 ?? 01 00 00 00 C7 44 24 ?? 02 00 00 00 FF 15 ?? ?? ?? ?? 48 8B C8 4C 8D 44 24 ?? 41 8D 56 ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 4C 24 ?? 4C 8D 44 24 ?? 4C 89 74 24 ?? 45 33 C9 33 D2 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 4C 24 ?? FF 15 ?? ?? ?? ?? 48 89 9C 24 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 89 B4 24 ?? ?? ?? ?? 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8B C8 FF 15 ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 84 ?? ?? ?? ?? 33 D2 48 8D 4D ?? 41 B8 04 01 00 00 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 75 ?? 66 0F 1F 44 00 ?? 48 8B 4C 24 ?? 4C 8D 45 ?? 41 B9 04 01 00 00 33 D2 FF 15 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 8D 4D ?? E8 ?? ?? ?? ?? 48 85 C0 75 ?? 33 D2 48 8D 4D ?? 41 B8 04 01 00 00 E8 ?? ?? ?? ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 BA 00 00 00 02 FF D3 85 C0 74 ?? 33 C0 E9 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 8B CB FF 15 ?? ?? ?? ?? 8B F0 48 85 DB 74 ?? 85 C0 74 ?? 4C 8D 4C 24 ?? 48 89 BC 24 ?? ?? ?? ?? BA FD 03 00 AC 41 B8 1F 00 10 00 48 8B CB FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 4C 89 74 24 ?? C7 44 24 ?? 80 00 00 00 48 8D 0D ?? ?? ?? ?? 45 33 C9 48 89 44 24 ?? 45 33 C0 C7 44 24 ?? 01 00 00 00 BA 00 00 00 10 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 8B F8 48 83 F8 FF 74 ?? 48 8B 4C 24 ?? 48 8D 44 24 ?? 48 89 44 24 ?? 41 B9 02 00 00 00 4C 89 74 24 ?? 4C 8B C7 8B D6 4C 89 74 24 ?? FF 15 ?? ?? ?? ?? 48 8B CB FF 15 ?? ?? ?? ?? 48 8B CF FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 8B 54 24 ?? 48 8B C8 FF 15 ?? ?? ?? ?? 33 C9 FF 15 ?? ?? ?? ?? CC 48 8B CB FF 15 ?? ?? ?? ?? 48 8B BC 24 ?? ?? ?? ?? 33 C0 48 8B B4 24 ?? ?? ?? ?? 48 8B 9C 24 ?? ?? ?? ?? 48 8B 8D ?? ?? ?? ?? 48 33 CC E8 ?? ?? ?? ?? 4C 8B B4 24 ?? ?? ?? ?? 48 81 C4 A0 01 00 00 5D C3 }
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and any of ($bytes*)
}

rule baseline_Builder_MSIL_SharpGenerator_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'SharpGenerator' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "3f450977-d796-4016-bb78-c9e91c6a0f08" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule baseline_APT_Loader_Win_PGF_2
{
    meta:
        description = "PE rich header matches PGF backdoor"
        md5 = "226b1ac427eb5a4dc2a00cc72c163214"
        md5_2 = "2398ed2d5b830d226af26dedaf30f64a"
        md5_3 = "24a7c99da9eef1c58f09cf09b9744d7b"
        md5_4 = "aeb0e1d0e71ce2a08db9b1e5fb98e0aa"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $rich1 = { A8 B7 17 3A EC D6 79 69 EC D6 79 69 EC D6 79 69 2F D9 24 69 E8 D6 79 69 E5 AE EC 69 EA D6 79 69 EC D6 78 69 A8 D6 79 69 E5 AE EA 69 EF D6 79 69 E5 AE FA 69 D0 D6 79 69 E5 AE EB 69 ED D6 79 69 E5 AE FD 69 E2 D6 79 69 CB 10 07 69 ED D6 79 69 E5 AE E8 69 ED D6 79 69 }
        $rich2 = { C1 CF 75 A4 85 AE 1B F7 85 AE 1B F7 85 AE 1B F7 8C D6 88 F7 83 AE 1B F7 0D C9 1A F6 87 AE 1B F7 0D C9 1E F6 8F AE 1B F7 0D C9 1F F6 8F AE 1B F7 0D C9 18 F6 84 AE 1B F7 DE C6 1A F6 86 AE 1B F7 85 AE 1A F7 BF AE 1B F7 84 C3 12 F6 81 AE 1B F7 84 C3 E4 F7 84 AE 1B F7 84 C3 19 F6 84 AE 1B F7 }
        $rich3 = { D6 60 82 B8 92 01 EC EB 92 01 EC EB 92 01 EC EB 9B 79 7F EB 94 01 EC EB 1A 66 ED EA 90 01 EC EB 1A 66 E9 EA 98 01 EC EB 1A 66 E8 EA 9A 01 EC EB 1A 66 EF EA 90 01 EC EB C9 69 ED EA 91 01 EC EB 92 01 ED EB AF 01 EC EB 93 6C E5 EA 96 01 EC EB 93 6C 13 EB 93 01 EC EB 93 6C EE EA 93 01 EC EB }
        $rich4 = { 41 36 64 33 05 57 0A 60 05 57 0A 60 05 57 0A 60 73 CA 71 60 01 57 0A 60 0C 2F 9F 60 04 57 0A 60 0C 2F 89 60 3D 57 0A 60 0C 2F 8E 60 0A 57 0A 60 05 57 0B 60 4A 57 0A 60 0C 2F 99 60 06 57 0A 60 73 CA 67 60 04 57 0A 60 0C 2F 98 60 04 57 0A 60 0C 2F 80 60 04 57 0A 60 22 91 74 60 04 57 0A 60 0C 2F 9B 60 04 57 0A 60 }
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and filesize < 15MB and (($rich1 at 128) or ($rich2 at 128) or ($rich3 at 128) or ($rich4 at 128))
}

rule baseline_Trojan_Win_Generic_101
{
    meta:
        description = "Detects FireEye Windows trojan"
        date = "2020-11-25"
        modified = "2020-11-25"
        md5 = "2e67c62bd0307c04af469ee8dcb220f2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s0 = { 2A [1-16] 17 [1-16] 02 04 00 00 [1-16] FF 15 }
        $s1 = { 81 7? [1-3] 02 04 00 00 7? [1-3] 83 7? [1-3] 17 7? [1-3] 83 7? [1-3] 2A 7? }
        $s2 = { FF 15 [4-16] FF D? [1-16] 3D [1-24] 89 [1-8] E8 [4-16] 89 [1-8] F3 A4 [1-24] E8 }
        $si1 = "PeekMessageA" fullword
        $si2 = "PostThreadMessageA" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and @s0[1] < @s1[1] and @s1[1] < @s2[1] and all of them
}

rule baseline_Loader_MSIL_CSharpSectionInjection_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'C_Sharp_SectionInjection' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "d77135da-0496-4b5c-9afe-e1590a4c136a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule baseline_APT_HackTool_MSIL_SHARPWEBCRAWLER_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'sharpwebcrawler' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "cf27abf4-ef35-46cd-8d0c-756630c686f1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule baseline_Trojan_Win64_Generic_22
{
    meta:
        description = "Detects FireEye's Windows Trojan"
        date = "2020-11-26"
        modified = "2020-11-26"
        md5 = "f7d9961463b5110a3d70ee2e97842ed3"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $api1 = "VirtualAllocEx" fullword
        $api2 = "UpdateProcThreadAttribute" fullword
        $api3 = "DuplicateTokenEx" fullword
        $api4 = "CreateProcessAsUserA" fullword
        $inject = { C7 44 24 20 40 00 00 00 33 D2 41 B9 00 30 00 00 41 B8 [4] 48 8B CB FF 15 [4] 48 8B F0 48 85 C0 74 ?? 4C 89 74 24 20 41 B9 [4] 4C 8D 05 [4] 48 8B D6 48 8B CB FF 15 [4] 85 C0 75 [5-10] 4C 8D 0C 3E 48 8D 44 24 ?? 48 89 44 24 30 44 89 74 24 28 4C 89 74 24 20 33 D2 41 B8 [4] 48 8B CB FF 15 }
        $process = { 89 74 24 30 ?? 8D 4C 24 [2] 89 74 24 28 33 D2 41 B8 00 00 02 00 48 C7 44 24 20 08 00 00 00 48 8B CF FF 15 [4] 85 C0 0F 84 [4] 48 8B [2-3] 48 8D 45 ?? 48 89 44 24 50 4C 8D 05 [4] 48 8D 45 ?? 48 89 7D 08 48 89 44 24 48 45 33 C9 ?? 89 74 24 40 33 D2 ?? 89 74 24 38 C7 44 24 30 04 00 08 00 [0-1] 89 74 24 28 ?? 89 74 24 20 FF 15 }
        $token = { FF 15 [4] 4C 8D 44 24 ?? BA 0A 00 00 00 48 8B C8 FF 15 [4] 85 C0 0F 84 [4] 48 8B 4C 24 ?? 48 8D [2-3] 41 B9 02 00 00 00 48 89 44 24 28 45 33 C0 C7 44 24 20 02 00 00 00 41 8D 51 09 FF 15 [4] 85 C0 0F 84 [4] 45 33 C0 4C 8D 4C 24 ?? 33 C9 41 8D 50 01 FF 15 }
    condition:
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and (uint16(uint32(0x3C)+0x18) == 0x020B)) and all of them
}

rule baseline_Trojan_MSIL_GORAT_Module_PowerShell_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'RedFlare - Module - PowerShell' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "38d89034-2dd9-4367-8a6e-5409827a243a" ascii nocase wide
        $typelibguid1 = "845ee9dc-97c9-4c48-834e-dc31ee007c25" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule baseline_HackTool_MSIL_PuppyHound_1
{
    meta:
        description = "This is a modification of an existing FireEye detection for SharpHound. However, it looks for the string 'PuppyHound' instead of 'SharpHound' as this is all that was needed to detect the PuppyHound variant of SharpHound."
        md5 = "eeedc09570324767a3de8205f66a5295"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $1 = "PuppyHound"
        $2 = "UserDomainKey"
        $3 = "LdapBuilder"
        $init = { 28 [2] 00 0A 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 72 [2] 00 70 1? ?? 28 [2] 00 0A 28 [2] 00 0A 0B 1F 2D }
        $msil = /\x00_Cor(Exe|Dll)Main\x00/
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

rule baseline_APT_Builder_PY_MATRYOSHKA_1
{
    meta:
        description = "Detects FireEye's Python MATRYOSHKA tool"
        date = "2020-12-02"
        modified = "2020-12-02"
        md5 = "25a97f6dba87ef9906a62c1a305ee1dd"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $s1 = ".pop(0)])"
        $s2 = "[1].replace('unsigned char buf[] = \"'"
        $s3 = "binascii.hexlify(f.read()).decode("
        $s4 = "os.system(\"cargo build {0} --bin {1}\".format("
        $s5 = "shutil.which('rustc')"
        $s6 = "~/.cargo/bin"
        $s7 = /[\x22\x27]\\\\x[\x22\x27]\.join\(\[\w{1,64}\[\w{1,64}:\w{1,64}[\x09\x20]{0,32}\+[\x09\x20]{0,32}2\]/
    condition:
        all of them
}

rule baseline_Loader_MSIL_RuralBishop_1b
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the public RuralBishop project."
        md5 = "09bdbad8358b04994e2c04bb26a160ef"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid1 = "FE4414D9-1D7E-4EEB-B781-D278FE7A5619" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $typelibguid1
}

rule baseline_APT_HackTool_MSIL_NOAMCI_1
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project. This rule looks for .NET PE files that contain the ProjectGuid found in the 'noamci' project."
        md5 = "dd8805d0e470e59b829d98397507d8c2"
        reference = "https://www.fireeye.com/blog/products-and-services/2020/12/fireeye-shares-details-of-recent-cyber-attack-actions-to-protect-community.html"
        author = "FireEye"
    strings:
        $typelibguid0 = "7bcccf21-7ecd-4fd4-8f77-06d461fd4d51" ascii nocase wide
        $typelibguid1 = "ef86214e-54de-41c3-b27f-efc61d0accc3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule baseline_MarathonTool {
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "084a27cd3404554cc799d0e689f65880e10b59e3"
	strings:
		$s0 = "MarathonTool" ascii
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
		$s18 = "SELECT UNICODE(SUBSTRING((system_user),{0},1))" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1040KB and all of them
}

rule baseline_PLUGIN_TracKid {
	meta:
		description = "Chinese Hacktool Set - file TracKid.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a114181b334e850d4b33e9be2794f5bb0eb59a09"
	strings:
		$s0 = "E-mail: cracker_prince@163.com" fullword ascii
		$s1 = ".\\TracKid Log\\%s.txt" fullword ascii
		$s2 = "Coded by prince" fullword ascii
		$s3 = "TracKid.dll" fullword ascii
		$s4 = ".\\TracKid Log" fullword ascii
		$s5 = "%08x -- %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}

rule baseline_Pc_pc2015 {
	meta:
		description = "Chinese Hacktool Set - file pc2015.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "de4f098611ac9eece91b079050b2d0b23afe0bcb"
	strings:
		$s0 = "\\svchost.exe" fullword ascii
		$s1 = "LON\\OD\\O-\\O)\\O%\\O!\\O=\\O9\\O5\\O1\\O" fullword ascii
		$s8 = "%s%08x.001" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 309KB and all of them
}


rule baseline_OtherTools_servu {
	meta:
		description = "Chinese Hacktool Set - file svu.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5c64e6879a9746a0d65226706e0edc7a"
	strings:
		$s0 = "MZKERNEL32.DLL" fullword ascii
		$s1 = "UpackByDwing@" fullword ascii
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "WriteFile" fullword ascii
	condition:
		uint32(0) == 0x454b5a4d and $s0 at 0 and filesize < 50KB and all of them
}

rule baseline_ustrrefadd {
	meta:
		description = "Chinese Hacktool Set - file ustrrefadd.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b371b122460951e74094f3db3016264c9c8a0cfa"
	strings:
		$s0 = "E-Mail  : admin@luocong.com" fullword ascii
		$s1 = "Homepage: http://www.luocong.com" fullword ascii
		$s2 = ": %d  -  " fullword ascii
		$s3 = "ustrreffix.dll" fullword ascii
		$s5 = "Ultra String Reference plugin v%d.%02d" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 320KB and all of them
}

rule baseline_APT10_Malware_Sample_Gen {
   meta:
      description = "APT 10 / Cloud Hopper malware campaign"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-06"
      score = 80
      type = "file"

   strings:
      /* C2 Servers */
      $c2_1 = "002562066559681.r3u8.com" ascii
      $c2_2 = "031168053846049.r3u8.com" ascii
      $c2_3 = "0625.have8000.com" ascii
      $c2_4 = "1.gadskysun.com" ascii
      $c2_5 = "100fanwen.com" ascii
      $c2_6 = "11.usyahooapis.com" ascii
      $c2_7 = "19518473326.r3u8.com" ascii
      $c2_8 = "1960445709311199.r3u8.com" ascii
      $c2_9 = "1j.www1.biz" ascii
      $c2_10 = "1z.itsaol.com" ascii
      $c2_11 = "2012yearleft.com" ascii
      $c2_12 = "2014.zzux.com" ascii
      $c2_13 = "202017845.r3u8.com" ascii
      $c2_14 = "2139465544784.r3u8.com" ascii
      $c2_15 = "2789203959848958.r3u8.com" ascii
      $c2_16 = "5590428449750026.r3u8.com" ascii
      $c2_17 = "5q.niushenghuo.info" ascii
      $c2_18 = "6r.suibian2010.info" ascii
      $c2_19 = "9gowg.tech" ascii
      $c2_20 = "Hamiltion.catholicmmb.com" ascii
      $c2_21 = "a.wubangtu.info" ascii
      $c2_22 = "a1.suibian2010.info" ascii
      $c2_24 = "abc.wikaba.com" ascii
      $c2_25 = "abcd120719.6600.org" ascii
      $c2_26 = "abcd120807.3322.org" ascii
      $c2_27 = "acc.emailfound.info" ascii
      $c2_28 = "acc.lehigtapp.com" ascii
      $c2_29 = "acsocietyy.com" ascii
      $c2_31 = "ad.webbooting.com" ascii
      $c2_32 = "additional.sexidude.com" ascii
      $c2_33 = "af.zyns.com" ascii
      $c2_34 = "afc.https443.org" ascii
      $c2_35 = "ako.ddns.us" ascii
      $c2_36 = "androidmusicapp.onmypc.us" ascii
      $c2_37 = "announcements.toythieves.com" ascii
      $c2_38 = "anvprn.com" ascii
      $c2_39 = "aotuo.9966.org" ascii
      $c2_40 = "apec.qtsofta.com" ascii
      $c2_41 = "app.lehigtapp.com" ascii
      $c2_42 = "apple.cmdnetview.com" ascii
      $c2_43 = "apple.defensewar.org" ascii
      $c2_44 = "apple.ikwb.com" ascii
      $c2_45 = "appledownload.ourhobby.com" ascii
      $c2_46 = "appleimages.itemdb.com" ascii
      $c2_47 = "appleimages.longmusic.com" ascii
      $c2_48 = "applelib120102.9966.org" ascii
      $c2_49 = "applemirror.organiccrap.com" ascii
      $c2_50 = "applemirror.squirly.info" ascii
      $c2_51 = "applemusic.isasecret.com" ascii
      $c2_52 = "applemusic.itemdb.com" ascii
      $c2_53 = "applemusic.wikaba.com" ascii
      $c2_54 = "applemusic.xxuz.com" ascii
      $c2_55 = "applemusic.zzux.com" ascii
      $c2_56 = "apples.sytes.net" ascii
      $c2_57 = "appleupdate.itemdb.com" ascii
      $c2_58 = "architectisusa.com" ascii
      $c2_59 = "area.wthelpdesk.com" ascii
      $c2_60 = "army.xxuz.com" ascii
      $c2_61 = "art.p6p6.net" ascii
      $c2_62 = "asfzx.x24hr.com" ascii
      $c2_64 = "availab.wikaba.com" ascii
      $c2_65 = "availability.justdied.com" ascii
      $c2_66 = "ba.my03.com" ascii
      $c2_67 = "baby.macforlinux.net" ascii
      $c2_68 = "baby.myie12.com" ascii
      $c2_69 = "baby.usmirocomney.net" ascii
      $c2_70 = "back.jungleheart.com" ascii
      $c2_71 = "back.mofa.dynamic-dns.net" ascii
      $c2_72 = "bak.have8000.com" ascii
      $c2_73 = "bak.ignorelist.com" ascii
      $c2_74 = "bak.un.dnsrd.com" ascii
      $c2_75 = "balance1.wikaba.com" ascii
      $c2_76 = "balk.n7go.com" ascii
      $c2_77 = "banana.cmdnetview.com" ascii
      $c2_78 = "barrybaker.6600.org" ascii
      $c2_79 = "bbs.jungleheart.com" ascii
      $c2_80 = "bdoncloud.com" ascii
      $c2_81 = "be.mrslove.com" ascii
      $c2_82 = "be.yourtrap.com" ascii
      $c2_83 = "belowto.com" ascii
      $c2_84 = "bethel.webhop.net" ascii
      $c2_85 = "bexm.cleansite.biz" ascii
      $c2_86 = "bezu.itemdb.com" ascii
      $c2_87 = "bk56.twilightparadox.com" ascii
      $c2_88 = "blaaaaaaaaaaaa.windowsupdate.3-a.net" ascii
      $c2_89 = "blog.defensewar.org" ascii
      $c2_90 = "brand.fartit.com" ascii
      $c2_91 = "bridgeluxlightmadness.com" ascii
      $c2_92 = "bulletproof.squirly.info" ascii
      $c2_93 = "cao.p6p6.net" ascii
      $c2_94 = "cata.qtsofta.com" ascii
      $c2_95 = "catholicmmb.com" ascii
      $c2_96 = "cc.dynamicdns.co.uk" ascii
      $c2_97 = "ccfchrist.com" ascii
      $c2_98 = "ccupdatedata.authorizeddns.net" ascii
      $c2_99 = "cd.usyahooapis.com" ascii
      $c2_100 = "cdn.incloud-go.com" ascii
      $c2_101 = "center.shenajou.com" ascii
      $c2_102 = "cgei493860.r3u8.com" ascii
      $c2_103 = "chaindungeons.com" ascii
      $c2_104 = "chibashiri.com" ascii
      $c2_105 = "childrenstow.com" ascii
      $c2_106 = "cia.ezua.com" ascii
      $c2_107 = "cia.toh.info" ascii
      $c2_108 = "ciaoci.chickenkiller.com" ascii
      $c2_109 = "civilwar123.authorizeddns.org" ascii
      $c2_110 = "civilwar520.onmypc.org" ascii
      $c2_111 = "ckusshani.com" ascii
      $c2_112 = "cloud-kingl.com" ascii
      $c2_113 = "cloud-maste.com" ascii
      $c2_114 = "cloudns.8800.org" ascii
      $c2_115 = "cmdnetview.com" ascii
      $c2_116 = "cms.sindeali.com" ascii
      $c2_117 = "cnnews.mylftv.com" ascii
      $c2_118 = "commissioner.shenajou.com" ascii
      $c2_119 = "commons.onedumb.com" ascii
      $c2_120 = "contactus.myddns.com" ascii
      $c2_121 = "contactus.onmypc.us" ascii
      $c2_122 = "contract.4mydomain.com" ascii
      $c2_123 = "contractus.qpoe.com" ascii
      $c2_124 = "contractus.zzux.com" ascii
      $c2_125 = "coreck.suayay.com" ascii
      $c2_128 = "ctdl.windowsupdate.itsaol.com" ascii
      $c2_129 = "ctdl.windowsupdate.nsatcdns.com" ascii
      $c2_130 = "ctldl.appledownload.ourhobby.com" ascii
      $c2_131 = "ctldl.applemusic.itemdb.com" ascii
      $c2_132 = "ctldl.itunesmusic.jkub.com" ascii
      $c2_133 = "ctldl.microsoftmusic.onedumb.com" ascii
      $c2_134 = "ctldl.microsoftupdate.qhigh.com" ascii
      $c2_135 = "ctldl.windowsupdate.authorizeddns.org" ascii
      $c2_136 = "ctldl.windowsupdate.authorizeddns.us" ascii
      $c2_137 = "ctldl.windowsupdate.dnset.com" ascii
      $c2_138 = "ctldl.windowsupdate.esmtp.biz" ascii
      $c2_139 = "ctldl.windowsupdate.ezua.com" ascii
      $c2_140 = "ctldl.windowsupdate.gettrials.com" ascii
      $c2_141 = "ctldl.windowsupdate.itsaol.com" ascii
      $c2_142 = "ctldl.windowsupdate.lflinkup.com" ascii
      $c2_143 = "ctldl.windowsupdate.mrface.com" ascii
      $c2_144 = "ctldl.windowsupdate.nsatcdns.com" ascii
      $c2_145 = "ctldl.windowsupdate.organiccrap.com" ascii
      $c2_146 = "ctldl.windowsupdate.x24hr.com" ascii
      $c2_147 = "cvnx.zyns.com" ascii
      $c2_148 = "cwiinatonal.com" ascii
      $c2_149 = "daddy.gostudyantivirus.com" ascii
      $c2_150 = "dcc.jimingroup.com" ascii
      $c2_151 = "dd.ddns.us" ascii
      $c2_152 = "de.onmypc.info" ascii
      $c2_153 = "dear.loveddos.com" ascii
      $c2_154 = "dec.seyesb.acmetoy.com" ascii
      $c2_155 = "dedgesuite.net" ascii
      $c2_156 = "dedydns.ns01.us" ascii
      $c2_157 = "defensewar.org" ascii
      $c2_158 = "demoones.com" ascii
      $c2_159 = "department.shenajou.com" ascii
      $c2_160 = "details.squirly.info" ascii
      $c2_161 = "development.shenajou.com" ascii
      $c2_162 = "devilcase.acmetoy.com" ascii
      $c2_163 = "dfgwerzc.3322.org" ascii
      $c2_164 = "dick.ccfchrist.com" ascii
      $c2_165 = "digsby.ourhobby.com" ascii
      $c2_166 = "disruptive.https443.net" ascii
      $c2_167 = "dlmix.ourdvs.com" ascii
      $c2_168 = "dnspoddwg.authorizeddns.org" ascii
      $c2_170 = "document.methoder.com" ascii
      $c2_171 = "document.shenajou.com" ascii
      $c2_172 = "domainnow.yourtrap.com" ascii
      $c2_173 = "download.applemusic.itemdb.com" ascii
      $c2_174 = "download.microsoftmusic.onedumb.com" ascii
      $c2_175 = "download.windowsupdate.authorizeddns.org" ascii
      $c2_176 = "download.windowsupdate.dedgesuite.net" ascii
      $c2_177 = "download.windowsupdate.dnset.com" ascii
      $c2_178 = "download.windowsupdate.itsaol.com" ascii
      $c2_179 = "download.windowsupdate.lflinkup.com" ascii
      $c2_180 = "download.windowsupdate.nsatcdns.com" ascii
      $c2_181 = "download.windowsupdate.x24hr.com" ascii
      $c2_182 = "downloadlink.mypicture.info" ascii
      $c2_183 = "drives.methoder.com" ascii
      $c2_184 = "dst.1dumb.com" ascii
      $c2_185 = "duosay.com" ascii
      $c2_186 = "dyncojinf.6600.org" ascii
      $c2_187 = "dynsbluecheck.7766.org" ascii
      $c2_188 = "ea.onmypc.info" ascii
      $c2_189 = "ea.rebatesrule.net" ascii
      $c2_190 = "edgar.ccfchrist.com" ascii
      $c2_191 = "ehshiroshima.mylftv.com" ascii
      $c2_192 = "emailfound.info" ascii
      $c2_193 = "eric-averyanov.wha.la" ascii
      $c2_194 = "essashi.com" ascii
      $c2_195 = "eu.acmetoy.com" ascii
      $c2_196 = "eu.wha.la" ascii
      $c2_197 = "eu.zzux.com" ascii
      $c2_198 = "everydayfilmlink.com" ascii
      $c2_199 = "ewe.toshste.com" ascii
      $c2_200 = "eweek.2waky.com" ascii
      $c2_201 = "exprenum.com" ascii
      $c2_202 = "express.lflinkup.com" ascii
      $c2_203 = "extraordinary.dynamic-dns.net" ascii
      $c2_204 = "f068v.site" ascii
      $c2_205 = "fabian.ccfchrist.com" ascii
      $c2_206 = "fastemail.dnsrd.com" ascii
      $c2_207 = "fastmail2.com" ascii
      $c2_208 = "fbi.sexxxy.biz" ascii
      $c2_209 = "fbi.zyns.com" ascii
      $c2_210 = "fcztqbg.zj.r3u8.com" ascii
      $c2_211 = "feed.jungleheart.com" ascii
      $c2_212 = "fftpoor.com" ascii
      $c2_213 = "fg.v4.download.windowsupdates.dnsrd.com" ascii
      $c2_214 = "fgipv6.download.windowsupdate.com.mwcname.com" ascii
      $c2_215 = "file.zzux.com" ascii
      $c2_216 = "files.architectisusa.com" ascii
      $c2_217 = "film.everydayfilmlink.com" ascii
      $c2_218 = "filmlist.everydayfilmlink.com" ascii
      $c2_219 = "findme.epac.to" ascii
      $c2_220 = "fire.mrface.com" ascii
      $c2_221 = "fish.toh.info" ascii
      $c2_222 = "fiveavmersi.websegoo.net" ascii
      $c2_223 = "fjs.wikaba.com" ascii
      $c2_224 = "flea.poulsenv.com" ascii
      $c2_225 = "flynews.edns.biz" ascii
      $c2_226 = "fo.mysecondarydns.com" ascii
      $c2_227 = "foal.wchildress.com" ascii
      $c2_228 = "follow.wha.la" ascii
      $c2_229 = "foo.shenajou.com" ascii
      $c2_230 = "for.ddns.mobi" ascii
      $c2_231 = "fr.wikaba.com" ascii
      $c2_232 = "franck.demoones.com" ascii
      $c2_233 = "ftp.2014.zzux.com" ascii
      $c2_234 = "ftp.additional.sexidude.com" ascii
      $c2_235 = "ftp.afc.https443.org" ascii
      $c2_236 = "ftp.announcements.toythieves.com" ascii
      $c2_237 = "ftp.apple.ikwb.com" ascii
      $c2_238 = "ftp.appledownload.ourhobby.com" ascii
      $c2_239 = "ftp.appleimages.itemdb.com" ascii
      $c2_240 = "ftp.appleimages.longmusic.com" ascii
      $c2_241 = "ftp.appleimages.organiccrap.com" ascii
      $c2_242 = "ftp.applemirror.organiccrap.com" ascii
      $c2_243 = "ftp.applemirror.squirly.info" ascii
      $c2_244 = "ftp.applemusic.isasecret.com" ascii
      $c2_245 = "ftp.applemusic.itemdb.com" ascii
      $c2_246 = "ftp.applemusic.wikaba.com" ascii
      $c2_247 = "ftp.applemusic.xxuz.com" ascii
      $c2_248 = "ftp.applemusic.zzux.com" ascii
      $c2_249 = "ftp.appleupdate.itemdb.com" ascii
      $c2_250 = "ftp.architectisusa.com" ascii
      $c2_251 = "ftp.asfzx.x24hr.com" ascii
      $c2_252 = "ftp.availab.wikaba.com" ascii
      $c2_253 = "ftp.availability.justdied.com" ascii
      $c2_254 = "ftp.back.jungleheart.com" ascii
      $c2_255 = "ftp.balance1.wikaba.com" ascii
      $c2_256 = "ftp.be.mrslove.com" ascii
      $c2_257 = "ftp.brand.fartit.com" ascii
      $c2_258 = "ftp.bulletproof.squirly.info" ascii
      $c2_259 = "ftp.cia.ezua.com" ascii
      $c2_260 = "ftp.cia.toh.info" ascii
      $c2_261 = "ftp.civilwar123.authorizeddns.org" ascii
      $c2_262 = "ftp.civilwar520.onmypc.org" ascii
      $c2_263 = "ftp.cloudfileserverbs.dynamicdns.co.uk" ascii
      $c2_264 = "ftp.cnnews.mylftv.com" ascii
      $c2_265 = "ftp.commons.onedumb.com" ascii
      $c2_266 = "ftp.contractus.qpoe.com" ascii
      $c2_267 = "ftp.cvnx.zyns.com" ascii
      $c2_268 = "ftp.de.onmypc.info" ascii
      $c2_269 = "ftp.details.squirly.info" ascii
      $c2_270 = "ftp.devilcase.acmetoy.com" ascii
      $c2_271 = "ftp.disruptive.https443.net" ascii
      $c2_272 = "ftp.domainnow.yourtrap.com" ascii
      $c2_273 = "ftp.ea.onmypc.info" ascii
      $c2_274 = "ftp.ehshiroshima.mylftv.com" ascii
      $c2_275 = "ftp.eric-averyanov.wha.la" ascii
      $c2_276 = "ftp.eu.acmetoy.com" ascii
      $c2_277 = "ftp.eu.wha.la" ascii
      $c2_278 = "ftp.eu.zzux.com" ascii
      $c2_279 = "ftp.fbi.sexxxy.biz" ascii
      $c2_280 = "ftp.file.zzux.com" ascii
      $c2_281 = "ftp.findme.epac.to" ascii
      $c2_282 = "ftp.fire.mrface.com" ascii
      $c2_283 = "ftp.fjs.wikaba.com" ascii
      $c2_284 = "ftp.fr.wikaba.com" ascii
      $c2_285 = "ftp.fuck.ikwb.com" ascii
      $c2_286 = "ftp.fuckmm.dns-dns.com" ascii
      $c2_287 = "ftp.generat.almostmy.com" ascii
      $c2_288 = "ftp.goldtoyota.com" ascii
      $c2_289 = "ftp.goodmusic.justdied.com" ascii
      $c2_290 = "ftp.helpus.ddns.info" ascii
      $c2_291 = "ftp.hii.qhigh.com" ascii
      $c2_292 = "ftp.innocent-isayev.sexidude.com" ascii
      $c2_293 = "ftp.invoices.sexxxy.biz" ascii
      $c2_294 = "ftp.iphone.vizvaz.com" ascii
      $c2_295 = "ftp.itlans.isasecret.com" ascii
      $c2_296 = "ftp.itunesdownload.jkub.com" ascii
      $c2_297 = "ftp.itunesdownload.wikaba.com" ascii
      $c2_298 = "ftp.itunesimages.itemdb.com" ascii
      $c2_299 = "ftp.itunesimages.itsaol.com" ascii
      $c2_300 = "ftp.itunesimages.qpoe.com" ascii
      $c2_301 = "ftp.itunesmirror.fartit.com" ascii
      $c2_302 = "ftp.itunesmirror.itsaol.com" ascii
      $c2_303 = "ftp.itunesmusic.ikwb.com" ascii
      $c2_304 = "ftp.itunesmusic.jetos.com" ascii
      $c2_305 = "ftp.itunesmusic.jkub.com" ascii
      $c2_306 = "ftp.itunesmusic.zzux.com" ascii
      $c2_307 = "ftp.itunesupdate.itsaol.com" ascii
      $c2_308 = "ftp.itunesupdates.organiccrap.com" ascii
      $c2_309 = "ftp.japanfilmsite.ikwb.com" ascii
      $c2_310 = "ftp.jimin.mymom.info" ascii
      $c2_311 = "ftp.jp.serveuser.com" ascii
      $c2_312 = "ftp.key.zzux.com" ascii
      $c2_313 = "ftp.knowledge.sellclassics.com" ascii
      $c2_314 = "ftp.lan.dynssl.com" ascii
      $c2_315 = "ftp.latestnews.epac.to" ascii
      $c2_316 = "ftp.latestnews.organiccrap.com" ascii
      $c2_317 = "ftp.leedong.longmusic.com" ascii
      $c2_318 = "ftp.macfee.mrface.com" ascii
      $c2_319 = "ftp.maffc.mrface.com" ascii
      $c2_320 = "ftp.malware.dsmtp.com" ascii
      $c2_321 = "ftp.manager.jetos.com" ascii
      $c2_322 = "ftp.martin.sellclassics.com" ascii
      $c2_323 = "ftp.mason.vizvaz.com" ascii
      $c2_324 = "ftp.mediapath.organiccrap.com" ascii
      $c2_325 = "ftp.microsoft.got-game.org" ascii
      $c2_326 = "ftp.microsoft.mrface.com" ascii
      $c2_327 = "ftp.microsoftimages.organiccrap.com" ascii
      $c2_328 = "ftp.microsoftmusic.mrbasic.com" ascii
      $c2_329 = "ftp.microsoftqckmanager.pcanywhere.net" ascii
      $c2_330 = "ftp.microsoftupdate.mrbasic.com" ascii
      $c2_331 = "ftp.microsoftupdate.qhigh.com" ascii
      $c2_332 = "ftp.micrsoftware.dsmtp.com" ascii
      $c2_333 = "ftp.mircsoft.compress.to" ascii
      $c2_334 = "ftp.mmy.ddns.us" ascii
      $c2_335 = "ftp.mod.jetos.com" ascii
      $c2_336 = "ftp.mofa.dynamic-dns.net" ascii
      $c2_337 = "ftp.mofa.ns01.info" ascii
      $c2_338 = "ftp.moscowdic.trickip.org" ascii
      $c2_339 = "ftp.msg.ezua.com" ascii
      $c2_340 = "ftp.musicfile.ikwb.com" ascii
      $c2_341 = "ftp.musicjj.zzux.com" ascii
      $c2_342 = "ftp.mymusicbox.vizvaz.com" ascii
      $c2_343 = "ftp.myphpwebsite.itsaol.com" ascii
      $c2_344 = "ftp.myrestroomimage.isasecret.com" ascii
      $c2_345 = "ftp.na.americanunfinished.com" ascii
      $c2_346 = "ftp.na.onmypc.org" ascii
      $c2_347 = "ftp.newsdata.jkub.com" ascii
      $c2_348 = "ftp.newsroom.cleansite.info" ascii
      $c2_349 = "ftp.no.authorizeddns.org" ascii
      $c2_350 = "ftp.nsa.mefound.com" ascii
      $c2_351 = "ftp.nt.mynumber.org" ascii
      $c2_352 = "ftp.nttdata.otzo.com" ascii
      $c2_353 = "ftp.nz.compress.to" ascii
      $c2_354 = "ftp.ol.almostmy.com" ascii
      $c2_355 = "ftp.oracleupdate.dns04.com" ascii
      $c2_356 = "ftp.portal.mrface.com" ascii
      $c2_357 = "ftp.portal.sendsmtp.com" ascii
      $c2_358 = "ftp.portalser.dynamic-dns.net" ascii
      $c2_359 = "ftp.praskovya-matveyeva.mefound.com" ascii
      $c2_360 = "ftp.praskovya-ulyanova.dumb1.com" ascii
      $c2_361 = "ftp.products.almostmy.com" ascii
      $c2_362 = "ftp.products.cleansite.us" ascii
      $c2_363 = "ftp.products.serveuser.com" ascii
      $c2_364 = "ftp.purchase.lflinkup.org" ascii
      $c2_365 = "ftp.recent.dns-stuff.com" ascii
      $c2_366 = "ftp.recent.fartit.com" ascii
      $c2_367 = "ftp.referred.gr8domain.biz" ascii
      $c2_368 = "ftp.referred.yourtrap.com" ascii
      $c2_369 = "ftp.register.ourhobby.com" ascii
      $c2_370 = "ftp.registration2.instanthq.com" ascii
      $c2_371 = "ftp.registrations.4pu.com" ascii
      $c2_372 = "ftp.registrations.organiccrap.com" ascii
      $c2_373 = "ftp.remeberdata.iownyour.org" ascii
      $c2_374 = "ftp.reserveds.onedumb.com" ascii
      $c2_375 = "ftp.rethem.almostmy.com" ascii
      $c2_376 = "ftp.sdmsg.onmypc.org" ascii
      $c2_377 = "ftp.se.toythieves.com" ascii
      $c2_378 = "ftp.secertnews.mrbasic.com" ascii
      $c2_379 = "ftp.senseye.ikwb.com" ascii
      $c2_380 = "ftp.senseye.mrbonus.com" ascii
      $c2_381 = "ftp.septdlluckysystem.jungleheart.com" ascii
      $c2_382 = "ftp.seraphim-yurieva.justdied.com" ascii
      $c2_383 = "ftp.serv.justdied.com" ascii
      $c2_384 = "ftp.server1.proxydns.com" ascii
      $c2_385 = "ftp.seyesb.acmetoy.com" ascii
      $c2_386 = "ftp.shugiin.jkub.com" ascii
      $c2_387 = "ftp.singed.otzo.com" ascii
      $c2_388 = "ftp.sstday.jkub.com" ascii
      $c2_389 = "ftp.support1.mrface.com" ascii
      $c2_390 = "ftp.supportus.mefound.com" ascii
      $c2_391 = "ftp.svc.dynssl.com" ascii
      $c2_392 = "ftp.synssl.dnset.com" ascii
      $c2_393 = "ftp.tamraj.fartit.com" ascii
      $c2_394 = "ftp.tfa.longmusic.com" ascii
      $c2_395 = "ftp.thunder.wikaba.com" ascii
      $c2_396 = "ftp.ticket.instanthq.com" ascii
      $c2_397 = "ftp.ticket.serveuser.com" ascii
      $c2_398 = "ftp.tokyofile.2waky.com" ascii
      $c2_399 = "ftp.tophost.dynamicdns.co.uk" ascii
      $c2_400 = "ftp.transfer.lflinkup.org" ascii
      $c2_401 = "ftp.transfer.mrbasic.com" ascii
      $c2_402 = "ftp.transfer.vizvaz.com" ascii
      $c2_403 = "ftp.ugreen.itemdb.com" ascii
      $c2_404 = "ftp.uk.dynamicdns.org.uk" ascii
      $c2_405 = "ftp.un.ddns.info" ascii
      $c2_406 = "ftp.un.dnsrd.com" ascii
      $c2_407 = "ftp.usa.itsaol.com" ascii
      $c2_408 = "ftp.well.itsaol.com" ascii
      $c2_409 = "ftp.well.mrbasic.com" ascii
      $c2_410 = "ftp.wike.wikaba.com" ascii
      $c2_411 = "ftp.windowfile.itemdb.com" ascii
      $c2_412 = "ftp.windowsimages.itemdb.com" ascii
      $c2_413 = "ftp.windowsimages.qhigh.com" ascii
      $c2_414 = "ftp.windowsmirrors.vizvaz.com" ascii
      $c2_415 = "ftp.windowsupdate.2waky.com" ascii
      $c2_416 = "ftp.windowsupdate.3-a.net" ascii
      $c2_417 = "ftp.windowsupdate.authorizeddns.us" ascii
      $c2_418 = "ftp.windowsupdate.dns05.com" ascii
      $c2_419 = "ftp.windowsupdate.esmtp.biz" ascii
      $c2_420 = "ftp.windowsupdate.ezua.com" ascii
      $c2_421 = "ftp.windowsupdate.fartit.com" ascii
      $c2_422 = "ftp.windowsupdate.gettrials.com" ascii
      $c2_423 = "ftp.windowsupdate.instanthq.com" ascii
      $c2_424 = "ftp.windowsupdate.jungleheart.com" ascii
      $c2_425 = "ftp.windowsupdate.lflink.com" ascii
      $c2_426 = "ftp.windowsupdate.mrface.com" ascii
      $c2_427 = "ftp.windowsupdate.mylftv.com" ascii
      $c2_428 = "ftp.windowsupdate.rebatesrule.net" ascii
      $c2_429 = "ftp.windowsupdate.sellclassics.com" ascii
      $c2_430 = "ftp.windowsupdate.serveusers.com" ascii
      $c2_431 = "ftp.yandexr.sellclassics.com" ascii
      $c2_432 = "fu.epac.to" ascii
      $c2_433 = "fuck.ikwb.com" ascii
      $c2_434 = "fuckanti.com" ascii
      $c2_435 = "fuckdd.8800.org" ascii
      $c2_436 = "fuckmm.8800.org" ascii
      $c2_437 = "fuckmm.dns-dns.com" ascii
      $c2_438 = "fukuoka.cloud-maste.com" ascii
      $c2_439 = "g3ypf.online" ascii
      $c2_440 = "gadskysun.com" ascii
      $c2_441 = "gavin.ccfchrist.com" ascii
      $c2_442 = "generat.almostmy.com" ascii
      $c2_443 = "generousd.hopto.org" ascii
      $c2_444 = "gensuzuki.6600.org" ascii
      $c2_446 = "gh.mysecondarydns.com" ascii
      $c2_447 = "gifuonlineshopping.mynumber.org" ascii
      $c2_448 = "glicense.shenajou.com" ascii
      $c2_449 = "globalnews.wikaba.com" ascii
      $c2_450 = "gmail.com.mailsserver.com" ascii
      $c2_451 = "gmpcw.com" ascii
      $c2_452 = "gold.polopurple.com" ascii
      $c2_453 = "goldtoyota.com" ascii
      $c2_454 = "goodmusic.justdied.com" ascii
      $c2_455 = "goodsampjp.com" ascii
      $c2_456 = "gooesdataios.instanthq.com" ascii
      $c2_457 = "google.macforlinux.net" ascii
      $c2_458 = "google.usrobothome.com" ascii
      $c2_459 = "googlemeail.com" ascii
      $c2_460 = "gostudyantivirus.com" ascii
      $c2_461 = "gostudymbaa.com" ascii
      $c2_462 = "gotourisma.com" ascii
      $c2_463 = "gt4study.com" ascii
      $c2_464 = "gtsofta.com" ascii
      $c2_465 = "haoyujd.info" ascii
      $c2_466 = "happy.workerisgood.com" ascii
      $c2_467 = "have8000.com" ascii
      $c2_468 = "helpus.ddns.info" ascii
      $c2_469 = "helshellfucde.8866.org" ascii
      $c2_470 = "hg8fmv.racing" ascii
      $c2_471 = "hii.qhigh.com" ascii
      $c2_472 = "hk.2012yearleft.com" ascii
      $c2_473 = "hk.cmdnetview.com" ascii
      $c2_474 = "hk.have8000.com" ascii
      $c2_475 = "hk.loveddos.com" ascii
      $c2_476 = "home.trickip.org" ascii
      $c2_477 = "hostport9.net" ascii
      $c2_478 = "hotmai.info" ascii
      $c2_479 = "hotmail.com.mailsserver.com" ascii
      $c2_480 = "hukuoka.cloud-maste.com" ascii
      $c2_481 = "iamges.itunesmusic.jkub.com" ascii
      $c2_482 = "ibmmsg.strangled.net" ascii
      $c2_483 = "icfeds.cf" ascii
      $c2_484 = "idpmus.hostport9.net" ascii
      $c2_486 = "im.suibian2010.info" ascii
      $c2_487 = "image.websago.info" ascii
      $c2_488 = "images.itunesmusic.jkub.com" ascii
      $c2_489 = "images.thedomais.info" ascii
      $c2_490 = "images.tyoto-go-jp.com" ascii
      $c2_491 = "images.windowsupdate.organiccrap.com" ascii
      $c2_492 = "imap.architectisusa.com" ascii
      $c2_493 = "imap.dnset.com" ascii
      $c2_494 = "imap.lflink.com" ascii
      $c2_495 = "imap.onmypc.net" ascii
      $c2_496 = "imap.ygto.com" ascii
      $c2_497 = "img.station155.com" ascii
      $c2_498 = "improvejpese.com" ascii
      $c2_499 = "incloud-go.com" ascii
      $c2_500 = "incloud-obert.com" ascii
      $c2_501 = "ingemar.catholicmmb.com" ascii
      $c2_502 = "innocent-isayev.sexidude.com" ascii
      $c2_503 = "innov-tec.com.ua" ascii
      $c2_504 = "inspgon.re26.com" ascii
      $c2_505 = "interpreter.shenajou.com" ascii
      $c2_506 = "invoices.sexxxy.biz" ascii
      $c2_508 = "iphone.vizvaz.com" ascii
      $c2_509 = "ipv4.applemusic.itemdb.com" ascii
      $c2_510 = "ipv4.itunesmusic.jkub.com" ascii
      $c2_511 = "ipv4.japanenvnews.qpoe.com" ascii
      $c2_512 = "ipv4.microsoftmusic.onedumb.com" ascii
      $c2_513 = "ipv4.microsoftupdate.mrbasic.com" ascii
      $c2_514 = "ipv4.microsoftupdate.qhigh.com" ascii
      $c2_515 = "ipv4.windowsupdate.3-a.net" ascii
      $c2_516 = "ipv4.windowsupdate.authorizeddns.org" ascii
      $c2_517 = "ipv4.windowsupdate.authorizeddns.us" ascii
      $c2_518 = "ipv4.windowsupdate.dnset.com" ascii
      $c2_519 = "ipv4.windowsupdate.esmtp.biz" ascii
      $c2_520 = "ipv4.windowsupdate.ezua.com" ascii
      $c2_521 = "ipv4.windowsupdate.fartit.com" ascii
      $c2_522 = "ipv4.windowsupdate.gettrials.com" ascii
      $c2_523 = "ipv4.windowsupdate.itsaol.com" ascii
      $c2_524 = "ipv4.windowsupdate.lflink.com" ascii
      $c2_525 = "ipv4.windowsupdate.lflinkup.com" ascii
      $c2_526 = "ipv4.windowsupdate.mrface.com" ascii
      $c2_527 = "ipv4.windowsupdate.mylftv.com" ascii
      $c2_528 = "ipv4.windowsupdate.nsatcdns.com" ascii
      $c2_529 = "ipv4.windowsupdate.x24hr.com" ascii
      $c2_530 = "ipv6microsoft.dlmix.ourdvs.com" ascii
      $c2_531 = "itlans.isasecret.com" ascii
      $c2_532 = "itunesdownload.jkub.com" ascii
      $c2_533 = "itunesdownload.vizvaz.com" ascii
      $c2_534 = "itunesdownload.wikaba.com" ascii
      $c2_535 = "itunesimages.itemdb.com" ascii
      $c2_536 = "itunesimages.itsaol.com" ascii
      $c2_537 = "itunesimages.qpoe.com" ascii
      $c2_538 = "itunesmirror.fartit.com" ascii
      $c2_539 = "itunesmirror.itsaol.com" ascii
      $c2_540 = "itunesmusic.ikwb.com" ascii
      $c2_541 = "itunesmusic.jetos.com" ascii
      $c2_542 = "itunesmusic.jkub.com" ascii
      $c2_543 = "itunesmusic.zzux.com" ascii
      $c2_544 = "itunesupdate.itsaol.com" ascii
      $c2_545 = "itunesupdates.organiccrap.com" ascii
      $c2_546 = "iw.mrslove.com" ascii
      $c2_547 = "ixrayeye.com" ascii
      $c2_548 = "james.tffghelth.com" ascii
      $c2_549 = "janpan.bigmoney.biz" ascii
      $c2_550 = "janpun.americanunfinished.com" ascii
      $c2_551 = "jap.japanmusicinfo.com" ascii
      $c2_552 = "japan.fuckanti.com" ascii
      $c2_553 = "japan.linuxforover.com" ascii
      $c2_554 = "japan.loveddos.com" ascii
      $c2_555 = "japanenvnews.qpoe.com" ascii
      $c2_556 = "japanfilmsite.ikwb.com" ascii
      $c2_557 = "japanfst.japanteam.org" ascii
      $c2_558 = "japanmusicinfo.com" ascii
      $c2_559 = "japanteam.org" ascii
      $c2_560 = "jcie.mofa.ns01.info" ascii
      $c2_561 = "jepsen.r3u8.com" ascii
      $c2_562 = "jica-go-jp.bike" ascii
      $c2_563 = "jica-go-jp.biz" ascii
      $c2_564 = "jimin-jp.biz" ascii
      $c2_565 = "jimin.jimindaddy.com" ascii
      $c2_566 = "jimin.mymom.info" ascii
      $c2_567 = "jimindaddy.com" ascii
      $c2_568 = "jimingroup.com" ascii
      $c2_569 = "jimintokoy.com" ascii
      $c2_570 = "jj.mysecondarydns.com" ascii
      $c2_571 = "jmuroran.com" ascii
      $c2_572 = "jp.rakutenmusic.com" ascii
      $c2_573 = "jp.serveuser.com" ascii
      $c2_574 = "jpcert.org" ascii
      $c2_575 = "jpn.longmusic.com" ascii
      $c2_576 = "jpnxzshopdata.authorizeddns.org" ascii
      $c2_577 = "jpstarmarket.serveusers.com" ascii
      $c2_578 = "kaka.lehigtapp.com" ascii
      $c2_579 = "kawasaki.cloud-maste.com" ascii
      $c2_580 = "kawasaki.unhamj.com" ascii
      $c2_581 = "kennedy.tffghelth.com" ascii
      $c2_582 = "key.zzux.com" ascii
      $c2_583 = "kikimusic.sellclassics.com" ascii
      $c2_584 = "kmd.crabdance.com" ascii
      $c2_585 = "knowledge.sellclassics.com" ascii
      $c2_586 = "ktgmktanxgvn.r3u8.com" ascii
      $c2_587 = "kxsbwappupdate.dhcp.biz" ascii
      $c2_588 = "kztmusiclnk.dnsrd.com" ascii
      $c2_589 = "lan.dynssl.com" ascii
      $c2_590 = "last.p6p6.net" ascii
      $c2_591 = "latestnews.epac.to" ascii
      $c2_592 = "latestnews.organiccrap.com" ascii
      $c2_593 = "leedong.longmusic.com" ascii
      $c2_594 = "lehigtapp.com" ascii
      $c2_595 = "lennon.fftpoor.com" ascii
      $c2_596 = "license.shenajou.com" ascii
      $c2_597 = "lie.jetos.com" ascii
      $c2_598 = "linuxforover.com" ascii
      $c2_599 = "linuxsofta.com" ascii
      $c2_600 = "lion.wchildress.com" ascii
      $c2_601 = "lizard.poulsenv.com" ascii
      $c2_602 = "logon-live.com" ascii
      $c2_603 = "lottedfstravel.webbooting.com" ascii
      $c2_604 = "loveddos.com" ascii
      $c2_605 = "lzf550.r3u8.com" ascii
      $c2_606 = "ma.vizvaz.com" ascii
      $c2_607 = "mac.goldtoyota.com" ascii
      $c2_608 = "mac.methoder.com" ascii
      $c2_609 = "macfee.mrface.com" ascii
      $c2_610 = "macforlinux.net" ascii
      $c2_611 = "maffc.mrface.com" ascii
      $c2_612 = "mail.architectisusa.com" ascii
      $c2_613 = "mail.macforlinux.net" ascii
      $c2_614 = "mailcarriage.co.uk" ascii
      $c2_615 = "mailj.hostport9.net" ascii
      $c2_616 = "mailserever.com" ascii
      $c2_617 = "mailsserver.com" ascii
      $c2_618 = "mailvserver.com" ascii
      $c2_619 = "malcolm.fftpoor.com" ascii
      $c2_620 = "malware.dsmtp.com" ascii
      $c2_621 = "manager.architectisusa.com" ascii
      $c2_622 = "manager.jetos.com" ascii
      $c2_623 = "markabcinfo.dynamicdns.me.uk" ascii
      $c2_624 = "martin.sellclassics.com" ascii
      $c2_625 = "mason.vizvaz.com" ascii
      $c2_626 = "mbaby.macforlinux.net" ascii
      $c2_627 = "medexplor.thedomais.info" ascii
      $c2_628 = "mediapath.organiccrap.com" ascii
      $c2_629 = "meiji-ac-jp.com" ascii
      $c2_630 = "mesjm.emailfound.info" ascii
      $c2_631 = "message.emailfound.info" ascii
      $c2_632 = "message.p6p6.net" ascii
      $c2_633 = "messagea.emailfound.info" ascii
      $c2_634 = "methoder.com" ascii
      $c2_635 = "mf.ddns.info" ascii
      $c2_636 = "microcnmlgb.3322.org" ascii
      $c2_637 = "microdef.2288.org" ascii
      $c2_638 = "microhome.wikaba.com" ascii
      $c2_639 = "microsoft.got-game.org" ascii
      $c2_640 = "microsoft.mrface.com" ascii
      $c2_641 = "microsoftdownload.zzux.com" ascii
      $c2_642 = "microsoftempowering.sendsmtp.com" ascii
      $c2_643 = "microsoften.com" ascii
      $c2_644 = "microsoftgame.mrface.com" ascii
      $c2_645 = "microsoftgetstarted.sexidude.com" ascii
      $c2_646 = "microsoftimages.organiccrap.com" ascii
      $c2_647 = "microsoftmirror.mrbasic.com" ascii
      $c2_648 = "microsoftmusic.itemdb.com" ascii
      $c2_649 = "microsoftmusic.mrbasic.com" ascii
      $c2_650 = "microsoftmusic.onedumb.com" ascii
      $c2_651 = "microsoftqckmanager.pcanywhere.net" ascii
      $c2_652 = "microsoftstore.jetos.com" ascii
      $c2_653 = "microsoftstores.itemdb.com" ascii
      $c2_654 = "microsoftupdate.mrbasic.com" ascii
      $c2_655 = "microsoftupdate.qhigh.com" ascii
      $c2_656 = "microsoftupdates.vizvaz.com" ascii
      $c2_657 = "micrsoftware.dsmtp.com" ascii
      $c2_658 = "mircsoft.compress.to" ascii
      $c2_659 = "mivsee.website0012.net" ascii
      $c2_660 = "mmofoojap.2288.org" ascii
      $c2_661 = "mmy.ddns.us" ascii
      $c2_662 = "mobile.2waky.com" ascii
      $c2_663 = "mocha.100fanwen.com" ascii
      $c2_664 = "mod.jetos.com" ascii
      $c2_665 = "mofa-go-jp.com" ascii
      $c2_666 = "mofa.dynamic-dns.net" ascii
      $c2_667 = "mofa.ns01.info" ascii
      $c2_668 = "mofa.strangled.net" ascii
      $c2_669 = "mofaess.com" ascii
      $c2_670 = "mongoles.3322.org" ascii
      $c2_671 = "monkey.2012yearleft.com" ascii
      $c2_672 = "moscowstdsupdate.toythieves.com" ascii
      $c2_673 = "mrsloveaqx.mrslove.com" ascii
      $c2_674 = "ms.ecc.u-tokyo-ac-jp.com" ascii
      $c2_675 = "mseupdate.ourhobby.com" ascii
      $c2_676 = "msg.ezua.com" ascii
      $c2_677 = "msn.incloud-go.com" ascii
      $c2_678 = "muller.exprenum.com" ascii
      $c2_679 = "music.applemusic.itemdb.com" ascii
      $c2_680 = "music.cleansite.us" ascii
      $c2_681 = "music.websegoo.net" ascii
      $c2_682 = "musicfile.ikwb.com" ascii
      $c2_683 = "musicinfo.everydayfilmlink.com" ascii
      $c2_684 = "musiclinker.jkub.com" ascii
      $c2_685 = "musicsecph.squirly.info" ascii
      $c2_686 = "mx.yetrula.eu" ascii
      $c2_687 = "myie12.com" ascii
      $c2_688 = "mymusicbox.lflinkup.org" ascii
      $c2_689 = "mymusicbox.vizvaz.com" ascii
      $c2_690 = "myphpwebsite.itsaol.com" ascii
      $c2_691 = "myrestroomimage.isasecret.com" ascii
      $c2_692 = "mytwhomeinst.sendsmtp.com" ascii
      $c2_693 = "myurinikoreaaps.ninth.biz" ascii
      $c2_694 = "na.americanunfinished.com" ascii
      $c2_695 = "na.onmypc.org" ascii
      $c2_696 = "nasa.xxuz.com" ascii
      $c2_697 = "nec.website0012.net" ascii
      $c2_698 = "news.100fanwen.com" ascii
      $c2_699 = "newsdata.jkub.com" ascii
      $c2_700 = "newsfile.toythieves.com" ascii
      $c2_701 = "newsreport.justdied.com" ascii
      $c2_702 = "newsroom.cleansite.info" ascii
      $c2_703 = "nezwq.ezua.com" ascii
      $c2_704 = "ngcc.8800.org" ascii
      $c2_705 = "niushenghuo.info" ascii
      $c2_706 = "nk10.belowto.com" ascii
      $c2_707 = "nk20.belowto.com" ascii
      $c2_708 = "nlddnsinfo.https443.org" ascii
      $c2_709 = "nmrx.mrbonus.com" ascii
      $c2_710 = "nn.dynssl.com" ascii
      $c2_711 = "no.authorizeddns.org" ascii
      $c2_712 = "node.mofaess.com" ascii
      $c2_713 = "nodns2.qipian.org" ascii
      $c2_714 = "nposnewsinfo.qhigh.com" ascii
      $c2_715 = "ns1.belowto.com" ascii
      $c2_716 = "ns1.tlchs2.ml" ascii
      $c2_717 = "ns2.belowto.com" ascii
      $c2_718 = "ns21.belowto.com" ascii
      $c2_719 = "ns22.belowto.com" ascii
      $c2_720 = "ns4.belowto.com" ascii
      $c2_721 = "ns5.belowto.com" ascii
      $c2_722 = "nsa.mefound.com" ascii
      $c2_723 = "nsatcdns.com" ascii
      $c2_724 = "nt.mynumber.org" ascii
      $c2_725 = "nttdata.otzo.com" ascii
      $c2_726 = "nunluck.re26.com" ascii
      $c2_727 = "nz.compress.to" ascii
      $c2_728 = "oipbl.com" ascii
      $c2_729 = "ol.almostmy.com" ascii
      $c2_730 = "oldbmwy.com" ascii
      $c2_731 = "oms.sindeali.com" ascii
      $c2_732 = "openmofa.8866.org" ascii
      $c2_733 = "oracleupdate.dns04.com" ascii
      $c2_734 = "osaka-jpgo.com" ascii
      $c2_735 = "outlook.otzo.com" ascii
      $c2_736 = "owlmedia.mefound.com" ascii
      $c2_737 = "p6p6.net" ascii
      $c2_738 = "peopleinfodata.3-a.net" ascii
      $c2_739 = "phptecinfohelp.itemdb.com" ascii
      $c2_740 = "pictures.everydayfilmlink.com" ascii
      $c2_741 = "pj.qpoe.com" ascii
      $c2_742 = "points.mofaess.com" ascii
      $c2_743 = "polopurple.com" ascii
      $c2_744 = "pop.architectisusa.com" ascii
      $c2_745 = "pop.loveddos.com" ascii
      $c2_746 = "portal.mrface.com" ascii
      $c2_747 = "portal.sendsmtp.com" ascii
      $c2_748 = "portalser.dynamic-dns.net" ascii
      $c2_749 = "poulsenv.com" ascii
      $c2_750 = "praskovya-matveyeva.mefound.com" ascii
      $c2_751 = "praskovya-ulyanova.dumb1.com" ascii
      $c2_752 = "premium.redforlinux.com" ascii
      $c2_753 = "products.almostmy.com" ascii
      $c2_754 = "products.cleansite.us" ascii
      $c2_755 = "products.serveuser.com" ascii
      $c2_756 = "program.acmetoy.com" ascii
      $c2_757 = "prrmes4019.r3u8.com" ascii
      $c2_758 = "purchase.lflinkup.org" ascii
      $c2_759 = "q6.niushenghuo.info" ascii
      $c2_760 = "qtsofta.com" ascii
      $c2_761 = "quick.oldbmwy.com" ascii
      $c2_762 = "r3u8.com" ascii
      $c2_763 = "radiorig.com" ascii
      $c2_764 = "rain.orctldl.windowsupdate.authorizeddns.us" ascii
      $c2_765 = "rakutenmusic.com" ascii
      $c2_766 = "rdns-4.infoproduto1.tk" ascii
      $c2_767 = "re26.com" ascii
      $c2_768 = "read.xxuz.com" ascii
      $c2_769 = "recent.dns-stuff.com" ascii
      $c2_770 = "recent.fartit.com" ascii
      $c2_771 = "record.hostport9.net" ascii
      $c2_772 = "record.webssl9.info" ascii
      $c2_773 = "record.wschandler.com" ascii
      $c2_774 = "redforlinux.com" ascii
      $c2_775 = "referred.gr8domain.biz" ascii
      $c2_776 = "referred.yourtrap.com" ascii
      $c2_777 = "register.ourhobby.com" ascii
      $c2_778 = "registration2.instanthq.com" ascii
      $c2_779 = "registrations.4pu.com" ascii
      $c2_780 = "registrations.organiccrap.com" ascii
      $c2_781 = "reports.tomorrowforgood.com" ascii
      $c2_782 = "reserveds.onedumb.com" ascii
      $c2_783 = "resources.applemusic.itemdb.com" ascii
      $c2_784 = "rethem.almostmy.com" ascii
      $c2_785 = "rg197.win" ascii
      $c2_786 = "rlbeiydn.hi.r3u8.com" ascii
      $c2_787 = "saiyo.exprenum.com" ascii
      $c2_788 = "sakai.unhamj.com" ascii
      $c2_789 = "salvaiona.com" ascii
      $c2_790 = "sappore.cloud-maste.com" ascii
      $c2_791 = "sapporo.cloud-maste.com" ascii
      $c2_792 = "sapporot.com" ascii
      $c2_793 = "sat.suayay.com" ascii
      $c2_794 = "saverd.re26.com" ascii
      $c2_795 = "sbuudd.webssl9.info" ascii
      $c2_796 = "sc.weboot.info" ascii
      $c2_797 = "scholz-versand.com" ascii
      $c2_798 = "scorpion.poulsenv.com" ascii
      $c2_799 = "scrlk.exprenum.com" ascii
      $c2_800 = "sdmsg.onmypc.org" ascii
      $c2_801 = "se.toythieves.com" ascii
      $c2_802 = "sea.websegoo.net" ascii
      $c2_803 = "secertnews.mrbasic.com" ascii
      $c2_804 = "secmicrosooo.6600.org" ascii
      $c2_805 = "secnetshit.com" ascii
      $c2_806 = "secserverupdate.toh.info" ascii
      $c2_807 = "sell.mofaess.com" ascii
      $c2_808 = "sema.linuxsofta.com" ascii
      $c2_809 = "send.have8000.com" ascii
      $c2_810 = "send.mofa.ns01.info" ascii
      $c2_811 = "sendmsg.jumpingcrab.com" ascii
      $c2_812 = "senseye.ikwb.com" ascii
      $c2_813 = "senseye.mrbonus.com" ascii
      $c2_814 = "septdlluckysystem.jungleheart.com" ascii
      $c2_815 = "seraphim-yurieva.justdied.com" ascii
      $c2_816 = "serv.justdied.com" ascii
      $c2_817 = "server1.proxydns.com" ascii
      $c2_818 = "seyesb.acmetoy.com" ascii
      $c2_819 = "sha.25u.com" ascii
      $c2_820 = "sha.ikwb.com" ascii
      $c2_821 = "shenajou.com" ascii
      $c2_822 = "shoppingcentre.station155.com" ascii
      $c2_823 = "shrimp.UsFfUnicef.com" ascii
      $c2_824 = "shrimp.bdoncloud.com" ascii
      $c2_825 = "shugiin.jkub.com" ascii
      $c2_826 = "sindeali.com" ascii
      $c2_827 = "singed.otzo.com" ascii
      $c2_828 = "siteinit.info" ascii
      $c2_829 = "sky.oldbmwy.com" ascii
      $c2_830 = "sma.jimindaddy.com" ascii
      $c2_831 = "smo.gadskysun.com" ascii
      $c2_832 = "smtp.architectisusa.com" ascii
      $c2_833 = "smtp.macforlinux.net" ascii
      $c2_834 = "smtp230.toldweb.com" ascii
      $c2_835 = "somthing.re26.com" ascii
      $c2_836 = "sstday.jkub.com" ascii
      $c2_837 = "start.usrobothome.com" ascii
      $c2_838 = "station155.com" ascii
      $c2_839 = "stevenlf.com" ascii
      $c2_840 = "stone.jumpingcrab.com" ascii
      $c2_841 = "style.u-tokyo-ac-jp.com" ascii
      $c2_842 = "suayay.com" ascii
      $c2_843 = "suibian2010.info" ascii
      $c2_844 = "support1.mrface.com" ascii
      $c2_845 = "supportus.mefound.com" ascii
      $c2_846 = "suzukigooogle.8866.org" ascii
      $c2_847 = "svc.dynssl.com" ascii
      $c2_848 = "synssl.dnset.com" ascii
      $c2_849 = "sz.thedomais.info" ascii
      $c2_850 = "taipei.yourtrap.com" ascii
      $c2_851 = "taipeifoodsite.ocry.com" ascii
      $c2_852 = "tamraj.fartit.com" ascii
      $c2_853 = "telegraph.mefound.com" ascii
      $c2_854 = "test.usyahooapis.com" ascii
      $c2_855 = "tfa.longmusic.com" ascii
      $c2_856 = "tffghelth.com" ascii
      $c2_857 = "thedomais.info" ascii
      $c2_858 = "ticket.instanthq.com" ascii
      $c2_859 = "ticket.jetos.com" ascii
      $c2_860 = "ticket.serveuser.com" ascii
      $c2_861 = "tidatacenter.shenajou.com" ascii
      $c2_862 = "tisdatacenter.shenajou.com" ascii
      $c2_863 = "tisupdateinfo.faqserv.com" ascii
      $c2_864 = "tokyo-gojp.com" ascii
      $c2_865 = "tokyofile.2waky.com" ascii
      $c2_866 = "tomorrowforgood.com" ascii
      $c2_867 = "tophost.dynamicdns.co.uk" ascii
      $c2_868 = "toshste.com" ascii
      $c2_869 = "toya.7766.org" ascii
      $c2_870 = "transfer.lflinkup.org" ascii
      $c2_871 = "transfer.mrbasic.com" ascii
      $c2_872 = "transfer.vizvaz.com" ascii
      $c2_873 = "trasul.mypicture.info" ascii
      $c2_874 = "travelyokogawafz.fartit.com" ascii
      $c2_875 = "trendmicroupdate.shenajou.com" ascii
      $c2_876 = "trendsecurity.shenajou.com" ascii
      $c2_877 = "trout.belowto.com" ascii
      $c2_878 = "tv.goldtoyota.com" ascii
      $c2_879 = "tw.2012yearleft.com" ascii
      $c2_880 = "twmusic.proxydns.com" ascii
      $c2_881 = "twpeoplemusicsite.my03.com" ascii
      $c2_882 = "twtravelinfomation.toythieves.com" ascii
      $c2_883 = "twx.mynumber.org" ascii
      $c2_884 = "tyoto-go-jp.com" ascii
      $c2_885 = "u-tokyo-ac-jp.com" ascii
      $c2_886 = "u1.FartIT.com" ascii
      $c2_887 = "u1.haoyujd.info" ascii
      $c2_888 = "ubuntusofta.com" ascii
      $c2_889 = "ugreen.itemdb.com" ascii
      $c2_890 = "ui.hdcdui.com" ascii
      $c2_891 = "uk.dynamicdns.org.uk" ascii
      $c2_892 = "ukuoka.cloud-maste.com" ascii
      $c2_893 = "ultimedia.vmmini.com" ascii
      $c2_894 = "un.ddns.info" ascii
      $c2_895 = "un.dnsrd.com" ascii
      $c2_896 = "unhamj.com" ascii
      $c2_897 = "update.yourtrap.com" ascii
      $c2_898 = "updatemirrors.fartit.com" ascii
      $c2_899 = "updates.itsaol.com" ascii
      $c2_900 = "ups.improvejpese.com" ascii
      $c2_901 = "urearapetsu.com" ascii
      $c2_902 = "usa.got-game.org" ascii
      $c2_903 = "usa.itsaol.com" ascii
      $c2_904 = "usa.japanteam.org" ascii
      $c2_905 = "usffunicef.com" ascii
      $c2_906 = "usmirocomney.net" ascii
      $c2_907 = "usrobothome.com" ascii
      $c2_908 = "usyahooapis.com" ascii
      $c2_909 = "uu.logon-live.com" ascii
      $c2_910 = "uu.niushenghuo.info" ascii
      $c2_911 = "ux.niushenghuo.info" ascii
      $c2_912 = "v4.appledownload.ourhobby.com" ascii
      $c2_913 = "v4.itunesmusic.jkub.com" ascii
      $c2_914 = "v4.microsoftmusic.onedumb.com" ascii
      $c2_915 = "v4.microsoftupdate.mrbasic.com" ascii
      $c2_916 = "v4.windowsupdate.DEDGESUITE.NET" ascii
      $c2_917 = "v4.windowsupdate.authorizeddns.org" ascii
      $c2_918 = "v4.windowsupdate.dnset.com" ascii
      $c2_919 = "v4.windowsupdate.itsaol.com" ascii
      $c2_920 = "v4.windowsupdate.lflinkup.com" ascii
      $c2_921 = "v4.windowsupdate.mrface.com" ascii
      $c2_922 = "v4.windowsupdate.nsatcdns.com" ascii
      $c2_923 = "v4.windowsupdate.x24hr.com" ascii
      $c2_924 = "v4.windowsupdates.dnsrd.com" ascii
      $c2_925 = "veryhuai.info" ascii
      $c2_926 = "video.vmdnsup.org" ascii
      $c2_927 = "vmdnsup.org" ascii
      $c2_929 = "vmyiersend.WEBSAGO.INFO" ascii
      $c2_930 = "vmyisan.website0012.net" ascii
      $c2_932 = "wchildress.com" ascii
      $c2_934 = "wcxh.mynetav.net" ascii
      $c2_935 = "wdsupdates.com" ascii
      $c2_936 = "webbooting.com" ascii
      $c2_937 = "webdirectnews.dynamicdns.biz" ascii
      $c2_938 = "webinfoseco.ygto.com" ascii
      $c2_939 = "webmailentry.jetos.com" ascii
      $c2_940 = "weboot.info" ascii
      $c2_941 = "websago.info" ascii
      $c2_942 = "websegoo.net" ascii
      $c2_943 = "website0012.net" ascii
      $c2_944 = "websiteboo.website0012.net" ascii
      $c2_945 = "websqlnewsmanager.ninth.biz" ascii
      $c2_946 = "webssl9.info" ascii
      $c2_947 = "well.itsaol.com" ascii
      $c2_948 = "well.mrbasic.com" ascii
      $c2_949 = "whale.toshste.com" ascii
      $c2_950 = "whellbuy.wschandler.com" ascii
      $c2_951 = "whyis.haoyujd.info" ascii
      $c2_952 = "wike.wikaba.com" ascii
      $c2_953 = "windowfile.itemdb.com" ascii
      $c2_954 = "windowsimages.itemdb.com" ascii
      $c2_955 = "windowsimages.qhigh.com" ascii
      $c2_956 = "windowsmirrors.vizvaz.com" ascii
      $c2_957 = "windowsstores.gettrials.com" ascii
      $c2_958 = "windowsstores.organiccrap.com" ascii
      $c2_959 = "windowsupdate.2waky.com" ascii
      $c2_960 = "windowsupdate.3-a.net" ascii
      $c2_961 = "windowsupdate.acmetoy.com" ascii
      $c2_962 = "windowsupdate.authorizeddns.net" ascii
      $c2_963 = "windowsupdate.authorizeddns.org" ascii
      $c2_964 = "windowsupdate.authorizeddns.us" ascii
      $c2_965 = "windowsupdate.com.mwcname.com" ascii
      $c2_966 = "windowsupdate.dedgesuite.net" ascii
      $c2_967 = "windowsupdate.dns05.com" ascii
      $c2_968 = "windowsupdate.dnset.com" ascii
      $c2_969 = "windowsupdate.esmtp.biz" ascii
      $c2_970 = "windowsupdate.ezua.com" ascii
      $c2_971 = "windowsupdate.fartit.com" ascii
      $c2_972 = "windowsupdate.gettrials.com" ascii
      $c2_973 = "windowsupdate.instanthq.com" ascii
      $c2_974 = "windowsupdate.itsaol.com" ascii
      $c2_975 = "windowsupdate.jungleheart.com" ascii
      $c2_976 = "windowsupdate.lflink.com" ascii
      $c2_977 = "windowsupdate.mrface.com" ascii
      $c2_978 = "windowsupdate.mylftv.com" ascii
      $c2_979 = "windowsupdate.nsatcdns.com" ascii
      $c2_980 = "windowsupdate.organiccrap.com" ascii
      $c2_981 = "windowsupdate.rebatesrule.net" ascii
      $c2_982 = "windowsupdate.sellclassics.com" ascii
      $c2_983 = "windowsupdate.serveusers.com" ascii
      $c2_984 = "windowsupdate.vizvaz.com" ascii
      $c2_985 = "windowsupdate.wcwname.com" ascii
      $c2_986 = "windowsupdate.x24hr.com" ascii
      $c2_987 = "windowsupdate.ygto.com" ascii
      $c2_988 = "windowsupdates.dnset.com" ascii
      $c2_989 = "windowsupdates.ezua.com" ascii
      $c2_990 = "windowsupdates.ikwb.com" ascii
      $c2_991 = "windowsupdates.itemdb.com" ascii
      $c2_992 = "windowsupdates.proxydns.com" ascii
      $c2_993 = "workerisgood.com" ascii
      $c2_994 = "woyaofanwen.com" ascii
      $c2_995 = "wschandler.com" ascii
      $c2_996 = "wthelpdesk.com" ascii
      $c2_997 = "wubangtu.info" ascii
      $c2_998 = "www-meti-go-jp.tyoto-go-jp.com" ascii
      $c2_999 = "www.2014.zzux.com" ascii
      $c2_1000 = "www.97sm.com" ascii
      $c2_1001 = "www.9gowg.tech" ascii
      $c2_1002 = "www.abdominal.faqserv.com" ascii
      $c2_1003 = "www.additional.sexidude.com" ascii
      $c2_1004 = "www.afc.https443.org" ascii
      $c2_1005 = "www.androidmusicapp.onmypc.us" ascii
      $c2_1006 = "www.announcements.toythieves.com" ascii
      $c2_1007 = "www.anx-own-334.mrbasic.com" ascii
      $c2_1008 = "www.apple.ikwb.com" ascii
      $c2_1009 = "www.appledownload.ourhobby.com" ascii
      $c2_1010 = "www.appleimages.itemdb.com" ascii
      $c2_1011 = "www.appleimages.longmusic.com" ascii
      $c2_1012 = "www.appleimages.organiccrap.com" ascii
      $c2_1013 = "www.applejuice.itemdb.com" ascii
      $c2_1014 = "www.applemirror.organiccrap.com" ascii
      $c2_1015 = "www.applemirror.squirly.info" ascii
      $c2_1016 = "www.applemusic.isasecret.com" ascii
      $c2_1017 = "www.applemusic.itemdb.com" ascii
      $c2_1018 = "www.applemusic.wikaba.com" ascii
      $c2_1019 = "www.applemusic.xxuz.com" ascii
      $c2_1020 = "www.applemusic.zzux.com" ascii
      $c2_1021 = "www.appleupdate.itemdb.com" ascii
      $c2_1022 = "www.appleupdateurl.2waky.com" ascii
      $c2_1023 = "www.architectisusa.com" ascii
      $c2_1024 = "www.army.xxuz.com" ascii
      $c2_1025 = "www.art.p6p6.net" ascii
      $c2_1026 = "www.asfzx.x24hr.com" ascii
      $c2_1027 = "www.availab.wikaba.com" ascii
      $c2_1028 = "www.availability.justdied.com" ascii
      $c2_1029 = "www.babymusicsitetr.mymom.info" ascii
      $c2_1030 = "www.back.jungleheart.com" ascii
      $c2_1031 = "www.balance1.wikaba.com" ascii
      $c2_1032 = "www.be.mrslove.com" ascii
      $c2_1033 = "www.belowto.com" ascii
      $c2_1034 = "www.billing.organiccrap.com" ascii
      $c2_1035 = "www.blaaaaaaaaaaaa.windowsupdate.3-a.net" ascii
      $c2_1036 = "www.brand.fartit.com" ascii
      $c2_1037 = "www.bulletproof.squirly.info" ascii
      $c2_1038 = "www.cabbage.iownyour.biz" ascii
      $c2_1039 = "www.ccupdatedata.authorizeddns.net" ascii
      $c2_1040 = "www.cdn.incloud-go.com" ascii
      $c2_1041 = "www.center.shenajou.com" ascii
      $c2_1042 = "www.chaindungeons.com" ascii
      $c2_1043 = "www.cia.ezua.com" ascii
      $c2_1044 = "www.cia.toh.info" ascii
      $c2_1045 = "www.civilwar123.authorizeddns.org" ascii
      $c2_1046 = "www.civilwar520.onmypc.org" ascii
      $c2_1047 = "www.cloud-maste.com" ascii
      $c2_1048 = "www.cnnews.mylftv.com" ascii
      $c2_1049 = "www.commissioner.shenajou.com" ascii
      $c2_1050 = "www.commons.onedumb.com" ascii
      $c2_1051 = "www.contractus.qpoe.com" ascii
      $c2_1052 = "www.corp-dnsonline.itsaol.com" ascii
      $c2_1053 = "www.courier.jetos.com" ascii
      $c2_1054 = "www.cress.mynetav.net" ascii
      $c2_1055 = "www.ctdl.windowsupdate.nsatcdns.com" ascii
      $c2_1056 = "www.ctldl.microsoftupdate.qhigh.com" ascii
      $c2_1057 = "www.ctldl.windowsupdate.authorizeddns.us" ascii
      $c2_1058 = "www.ctldl.windowsupdate.esmtp.biz" ascii
      $c2_1059 = "www.ctldl.windowsupdate.mrface.com" ascii
      $c2_1060 = "www.cwiinatonal.com" ascii
      $c2_1061 = "www.dasoftactivemodule.toythieves.com" ascii
      $c2_1062 = "www.dasonews.youdontcare.com" ascii
      $c2_1063 = "www.daughter.vizvaz.com" ascii
      $c2_1064 = "www.de.onmypc.info" ascii
      $c2_1065 = "www.details.squirly.info" ascii
      $c2_1066 = "www.development.shenajou.com" ascii
      $c2_1067 = "www.devilcase.acmetoy.com" ascii
      $c2_1068 = "www.disruptive.https443.net" ascii
      $c2_1069 = "www.dns-hinettw.25u.com" ascii
      $c2_1070 = "www.document.shenajou.com" ascii
      $c2_1071 = "www.domainnow.yourtrap.com" ascii
      $c2_1072 = "www.download.windowsupdate.nsatcdns.com" ascii
      $c2_1073 = "www.ea.onmypc.info" ascii
      $c2_1074 = "www.eddo.qpoe.com" ascii
      $c2_1075 = "www.ehshiroshima.mylftv.com" ascii
      $c2_1076 = "www.eric-averyanov.wha.la" ascii
      $c2_1077 = "www.eu.acmetoy.com" ascii
      $c2_1078 = "www.eu.wha.la" ascii
      $c2_1079 = "www.express.lflinkup.com" ascii
      $c2_1080 = "www.extraordinary.dynamic-dns.net" ascii
      $c2_1081 = "www.f068v.site" ascii
      $c2_1082 = "www.facefile.fartit.com" ascii
      $c2_1083 = "www.fertile.authorizeddns.net" ascii
      $c2_1084 = "www.file.zzux.com" ascii
      $c2_1085 = "www.findme.epac.to" ascii
      $c2_1086 = "www.fire.mrface.com" ascii
      $c2_1087 = "www.firstnews.jkub.com" ascii
      $c2_1088 = "www.fjs.wikaba.com" ascii
      $c2_1089 = "www.foal.wchildress.com" ascii
      $c2_1090 = "www.fr.wikaba.com" ascii
      $c2_1091 = "www.freegamecenter.onedumb.com" ascii
      $c2_1092 = "www.fruit.qhigh.com" ascii
      $c2_1093 = "www.fuck.ikwb.com" ascii
      $c2_1094 = "www.fuckmm.dns-dns.com" ascii
      $c2_1095 = "www.fukuoka.cloud-maste.com" ascii
      $c2_1096 = "www.g3ypf.online" ascii
      $c2_1097 = "www.garlic.dyndns.pro" ascii
      $c2_1098 = "www.generat.almostmy.com" ascii
      $c2_1099 = "www.glicense.shenajou.com" ascii
      $c2_1100 = "www.goldtoyota.com" ascii
      $c2_1101 = "www.goodmusic.justdied.com" ascii
      $c2_1102 = "www.gooesdataios.instanthq.com" ascii
      $c2_1103 = "www.grammar.jkub.com" ascii
      $c2_1104 = "www.helpus.ddns.info" ascii
      $c2_1105 = "www.hii.qhigh.com" ascii
      $c2_1106 = "www.hinetonlinedns.dns05.com" ascii
      $c2_1107 = "www.incloud-go.com" ascii
      $c2_1108 = "www.innocent-isayev.sexidude.com" ascii
      $c2_1109 = "www.interpreter.shenajou.com" ascii
      $c2_1110 = "www.invoices.sexxxy.biz" ascii
      $c2_1111 = "www.iphone.vizvaz.com" ascii
      $c2_1112 = "www.ipv4.microsoftupdate.mrbasic.com" ascii
      $c2_1113 = "www.ipv4.windowsupdate.3-a.net" ascii
      $c2_1114 = "www.ipv4.windowsupdate.esmtp.biz" ascii
      $c2_1115 = "www.ipv4.windowsupdate.fartit.com" ascii
      $c2_1116 = "www.ipv4.windowsupdate.lflink.com" ascii
      $c2_1117 = "www.ipv4.windowsupdate.mrface.com" ascii
      $c2_1118 = "www.ipv4.windowsupdate.mylftv.com" ascii
      $c2_1119 = "www.ipv4.windowsupdate.nsatcdns.com" ascii
      $c2_1120 = "www.itlans.isasecret.com" ascii
      $c2_1121 = "www.itunesdownload.jkub.com" ascii
      $c2_1122 = "www.itunesdownload.vizvaz.com" ascii
      $c2_1123 = "www.itunesdownload.wikaba.com" ascii
      $c2_1124 = "www.itunesimages.itemdb.com" ascii
      $c2_1125 = "www.itunesimages.itsaol.com" ascii
      $c2_1126 = "www.itunesimages.qpoe.com" ascii
      $c2_1127 = "www.itunesmirror.fartit.com" ascii
      $c2_1128 = "www.itunesmirror.itsaol.com" ascii
      $c2_1129 = "www.itunesmusic.ikwb.com" ascii
      $c2_1130 = "www.itunesmusic.jetos.com" ascii
      $c2_1131 = "www.itunesmusic.jkub.com" ascii
      $c2_1132 = "www.itunesmusic.zzux.com" ascii
      $c2_1133 = "www.itunesupdate.itsaol.com" ascii
      $c2_1134 = "www.itunesupdates.organiccrap.com" ascii
      $c2_1135 = "www.japanenvnews.qpoe.com" ascii
      $c2_1136 = "www.jd978.com" ascii
      $c2_1137 = "www.jimin.jimindaddy.com" ascii
      $c2_1138 = "www.jimin.mymom.info" ascii
      $c2_1139 = "www.jp.serveuser.com" ascii
      $c2_1140 = "www.jpnappstore.ourhobby.com" ascii
      $c2_1141 = "www.jpnewslogs.sendsmtp.com" ascii
      $c2_1142 = "www.jpnxzshopdata.authorizeddns.org" ascii
      $c2_1143 = "www.kawasaki.cloud-maste.com" ascii
      $c2_1144 = "www.kawasaki.unhamj.com" ascii
      $c2_1145 = "www.key.zzux.com" ascii
      $c2_1146 = "www.knowledge.sellclassics.com" ascii
      $c2_1147 = "www.lan.dynssl.com" ascii
      $c2_1148 = "www.last.p6p6.net" ascii
      $c2_1149 = "www.latestnews.epac.to" ascii
      $c2_1150 = "www.latestnews.organiccrap.com" ascii
      $c2_1151 = "www.leedong.longmusic.com" ascii
      $c2_1152 = "www.leeks.mrbonus.com" ascii
      $c2_1153 = "www.liberty.acmetoy.com" ascii
      $c2_1154 = "www.license.shenajou.com" ascii
      $c2_1155 = "www.lion.wchildress.com" ascii
      $c2_1156 = "www.loveddos.com" ascii
      $c2_1157 = "www.macfee.mrface.com" ascii
      $c2_1158 = "www.macforlinux.net" ascii
      $c2_1159 = "www.maffc.mrface.com" ascii
      $c2_1160 = "www.malware.dsmtp.com" ascii
      $c2_1161 = "www.manager.jetos.com" ascii
      $c2_1162 = "www.markabcinfo.dynamicdns.me.uk" ascii
      $c2_1163 = "www.mason.vizvaz.com" ascii
      $c2_1164 = "www.mediapath.organiccrap.com" ascii
      $c2_1165 = "www.meiji-ac-jp.com" ascii
      $c2_1166 = "www.messagea.emailfound.info" ascii
      $c2_1167 = "www.microsoft.got-game.org" ascii
      $c2_1168 = "www.microsoft.mrface.com" ascii
      $c2_1169 = "www.microsoftempowering.sendsmtp.com" ascii
      $c2_1170 = "www.microsoftgame.mrface.com" ascii
      $c2_1171 = "www.microsoftgetstarted.sexidude.com" ascii
      $c2_1172 = "www.microsoftimages.organiccrap.com" ascii
      $c2_1173 = "www.microsoftmirror.mrbasic.com" ascii
      $c2_1174 = "www.microsoftmusic.itemdb.com" ascii
      $c2_1175 = "www.microsoftmusic.mrbasic.com" ascii
      $c2_1176 = "www.microsoftqckmanager.pcanywhere.net" ascii
      $c2_1177 = "www.microsoftupdate.mrbasic.com" ascii
      $c2_1178 = "www.microsoftupdate.qhigh.com" ascii
      $c2_1179 = "www.micrsoftware.dsmtp.com" ascii
      $c2_1180 = "www.mircsoft.compress.to" ascii
      $c2_1181 = "www.mmy.ddns.us" ascii
      $c2_1182 = "www.mod.jetos.com" ascii
      $c2_1183 = "www.mofa.dynamic-dns.net" ascii
      $c2_1184 = "www.mofa.ns01.info" ascii
      $c2_1185 = "www.moonnightthse.zyns.com" ascii
      $c2_1186 = "www.moscowdic.trickip.org" ascii
      $c2_1187 = "www.moscowstdsupdate.toythieves.com" ascii
      $c2_1188 = "www.mseupdate.ourhobby.com" ascii
      $c2_1189 = "www.msg.ezua.com" ascii
      $c2_1190 = "www.msn.incloud-go.com" ascii
      $c2_1191 = "www.musicfile.ikwb.com" ascii
      $c2_1192 = "www.musicjj.zzux.com" ascii
      $c2_1193 = "www.musicsecph.squirly.info" ascii
      $c2_1194 = "www.mymusicbox.lflinkup.org" ascii
      $c2_1195 = "www.mymusicbox.vizvaz.com" ascii
      $c2_1196 = "www.myrestroomimage.isasecret.com" ascii
      $c2_1197 = "www.mytwhomeinst.sendsmtp.com" ascii
      $c2_1198 = "www.myurinikoreaaps.ninth.biz" ascii
      $c2_1199 = "www.na.americanunfinished.com" ascii
      $c2_1200 = "www.na.onmypc.org" ascii
      $c2_1201 = "www.networkjpnzee.mynetav.org" ascii
      $c2_1202 = "www.newcityoforward.rebatesrule.net" ascii
      $c2_1203 = "www.newdnssec-info.4mydomain.com" ascii
      $c2_1204 = "www.newsdata.jkub.com" ascii
      $c2_1205 = "www.newsfile.toythieves.com" ascii
      $c2_1206 = "www.newsroom.cleansite.info" ascii
      $c2_1207 = "www.nlddnsinfo.https443.org" ascii
      $c2_1208 = "www.no.authorizeddns.org" ascii
      $c2_1209 = "www.nposnewsinfo.qhigh.com" ascii
      $c2_1210 = "www.nsa.mefound.com" ascii
      $c2_1211 = "www.nt.mynumber.org" ascii
      $c2_1212 = "www.nttdata.otzo.com" ascii
      $c2_1213 = "www.nuisance.serveusers.com" ascii
      $c2_1214 = "www.nz.compress.to" ascii
      $c2_1215 = "www.ol.almostmy.com" ascii
      $c2_1216 = "www.oldbmwy.com" ascii
      $c2_1217 = "www.onion.jkub.com" ascii
      $c2_1218 = "www.onlinednsserver.sendsmtp.com" ascii
      $c2_1219 = "www.oracleupdate.dns04.com" ascii
      $c2_1220 = "www.oyster.jkub.com" ascii
      $c2_1221 = "www.p6p6.net" ascii
      $c2_1222 = "www.packetsdsquery.dns05.com" ascii
      $c2_1223 = "www.pepper.sexxxy.biz" ascii
      $c2_1224 = "www.phptecinfohelp.itemdb.com" ascii
      $c2_1225 = "www.pickled.myddns.com" ascii
      $c2_1226 = "www.polopurple.com" ascii
      $c2_1227 = "www.portal.mrface.com" ascii
      $c2_1228 = "www.portal.sendsmtp.com" ascii
      $c2_1229 = "www.portalser.dynamic-dns.net" ascii
      $c2_1230 = "www.praskovya-matveyeva.mefound.com" ascii
      $c2_1231 = "www.praskovya-ulyanova.dumb1.com" ascii
      $c2_1232 = "www.products.almostmy.com" ascii
      $c2_1233 = "www.products.cleansite.us" ascii
      $c2_1234 = "www.products.serveuser.com" ascii
      $c2_1235 = "www.purchase.lflinkup.org" ascii
      $c2_1236 = "www.rainbow.mypop3.org" ascii
      $c2_1237 = "www.re26.com" ascii
      $c2_1238 = "www.read.xxuz.com" ascii
      $c2_1239 = "www.recent.dns-stuff.com" ascii
      $c2_1240 = "www.recent.fartit.com" ascii
      $c2_1241 = "www.redflower.isasecret.com" ascii
      $c2_1242 = "www.referred.gr8domain.biz" ascii
      $c2_1243 = "www.referred.yourtrap.com" ascii
      $c2_1244 = "www.register.ourhobby.com" ascii
      $c2_1245 = "www.registration2.instanthq.com" ascii
      $c2_1246 = "www.registrations.4pu.com" ascii
      $c2_1247 = "www.registrations.organiccrap.com" ascii
      $c2_1248 = "www.remeberdata.iownyour.org" ascii
      $c2_1249 = "www.reserveds.onedumb.com" ascii
      $c2_1250 = "www.rethem.almostmy.com" ascii
      $c2_1251 = "www.rg197.win" ascii
      $c2_1252 = "www.sakai.unhamj.com" ascii
      $c2_1253 = "www.sapporo.cloud-maste.com" ascii
      $c2_1254 = "www.sauerkraut.sellclassics.com" ascii
      $c2_1255 = "www.saverd.re26.com" ascii
      $c2_1256 = "www.sbuudd.webssl9.info" ascii
      $c2_1257 = "www.sdmsg.onmypc.org" ascii
      $c2_1258 = "www.se.toythieves.com" ascii
      $c2_1259 = "www.secertnews.mrbasic.com" ascii
      $c2_1260 = "www.secnetshit.com" ascii
      $c2_1261 = "www.secserverupdate.toh.info" ascii
      $c2_1262 = "www.senseye.ikwb.com" ascii
      $c2_1263 = "www.senseye.mrbonus.com" ascii
      $c2_1264 = "www.septdlluckysystem.jungleheart.com" ascii
      $c2_1265 = "www.seraphim-yurieva.justdied.com" ascii
      $c2_1266 = "www.serv.justdied.com" ascii
      $c2_1267 = "www.server1.proxydns.com" ascii
      $c2_1268 = "www.seyesb.acmetoy.com" ascii
      $c2_1269 = "www.showy.almostmy.com" ascii
      $c2_1270 = "www.shugiin.jkub.com" ascii
      $c2_1271 = "www.sindeali.com" ascii
      $c2_1272 = "www.singed.otzo.com" ascii
      $c2_1273 = "www.sojourner.mypicture.info" ascii
      $c2_1274 = "www.sstday.jkub.com" ascii
      $c2_1275 = "www.support1.mrface.com" ascii
      $c2_1276 = "www.supportus.mefound.com" ascii
      $c2_1277 = "www.svc.dynssl.com" ascii
      $c2_1278 = "www.sweetheart.sexxxy.biz" ascii
      $c2_1279 = "www.synssl.dnset.com" ascii
      $c2_1280 = "www.tamraj.fartit.com" ascii
      $c2_1281 = "www.telegraph.mefound.com" ascii
      $c2_1282 = "www.tfa.longmusic.com" ascii
      $c2_1283 = "www.thunder.wikaba.com" ascii
      $c2_1284 = "www.ticket.instanthq.com" ascii
      $c2_1285 = "www.ticket.serveuser.com" ascii
      $c2_1286 = "www.tisupdateinfo.faqserv.com" ascii
      $c2_1287 = "www.tokyofile.2waky.com" ascii
      $c2_1288 = "www.tophost.dynamicdns.co.uk" ascii
      $c2_1289 = "www.transfer.lflinkup.org" ascii
      $c2_1290 = "www.transfer.mrbasic.com" ascii
      $c2_1291 = "www.transfer.vizvaz.com" ascii
      $c2_1292 = "www.twgovernmentinfo.acmetoy.com" ascii
      $c2_1293 = "www.twsslpopservupro.dynssl.com" ascii
      $c2_1294 = "www.ugreen.itemdb.com" ascii
      $c2_1295 = "www.uk.dynamicdns.org.uk" ascii
      $c2_1296 = "www.un.ddns.info" ascii
      $c2_1297 = "www.un.dnsrd.com" ascii
      $c2_1298 = "www.unhamj.com" ascii
      $c2_1299 = "www.usa.itsaol.com" ascii
      $c2_1300 = "www.usffunicef.com" ascii
      $c2_1301 = "www.usliveupdateonline.ygto.com" ascii
      $c2_1302 = "www.ut-portal-u-tokyo-ac-jp.tyoto-go-jp.com" ascii
      $c2_1303 = "www.v4.windowsupdate.mrface.com" ascii
      $c2_1304 = "www.v4.windowsupdate.nsatcdns.com" ascii
      $c2_1305 = "www.vmmini.com" ascii
      $c2_1306 = "www.wchildress.com" ascii
      $c2_1307 = "www.webdirectnews.dynamicdns.biz" ascii
      $c2_1308 = "www.webmailentry.jetos.com" ascii
      $c2_1309 = "www.websqlnewsmanager.ninth.biz" ascii
      $c2_1310 = "www.well.itsaol.com" ascii
      $c2_1311 = "www.well.mrbasic.com" ascii
      $c2_1312 = "www.windowfile.itemdb.com" ascii
      $c2_1313 = "www.windowsimages.itemdb.com" ascii
      $c2_1314 = "www.windowsimages.qhigh.com" ascii
      $c2_1315 = "www.windowsmirrors.vizvaz.com" ascii
      $c2_1316 = "www.windowsupdate.2waky.com" ascii
      $c2_1317 = "www.windowsupdate.3-a.net" ascii
      $c2_1318 = "www.windowsupdate.acmetoy.com" ascii
      $c2_1319 = "www.windowsupdate.authorizeddns.net" ascii
      $c2_1320 = "www.windowsupdate.authorizeddns.org" ascii
      $c2_1321 = "www.windowsupdate.authorizeddns.us" ascii
      $c2_1322 = "www.windowsupdate.dns05.com" ascii
      $c2_1323 = "www.windowsupdate.dnset.com" ascii
      $c2_1324 = "www.windowsupdate.esmtp.biz" ascii
      $c2_1325 = "www.windowsupdate.ezua.com" ascii
      $c2_1326 = "www.windowsupdate.fartit.com" ascii
      $c2_1327 = "www.windowsupdate.gettrials.com" ascii
      $c2_1328 = "www.windowsupdate.instanthq.com" ascii
      $c2_1329 = "www.windowsupdate.itsaol.com" ascii
      $c2_1330 = "www.windowsupdate.jungleheart.com" ascii
      $c2_1331 = "www.windowsupdate.lflink.com" ascii
      $c2_1332 = "www.windowsupdate.mrface.com" ascii
      $c2_1333 = "www.windowsupdate.mylftv.com" ascii
      $c2_1334 = "www.windowsupdate.nsatcdns.com" ascii
      $c2_1335 = "www.windowsupdate.organiccrap.com" ascii
      $c2_1336 = "www.windowsupdate.rebatesrule.net" ascii
      $c2_1337 = "www.windowsupdate.sellclassics.com" ascii
      $c2_1338 = "www.windowsupdate.serveusers.com" ascii
      $c2_1339 = "www.windowsupdate.x24hr.com" ascii
      $c2_1340 = "www.yahoo.incloud-go.com" ascii
      $c2_1341 = "www.yandexr.sellclassics.com" ascii
      $c2_1342 = "www.yeahyeahyeahs.3322.org" ascii
      $c2_1343 = "www.yokohamajpinstaz.mrbonus.com" ascii
      $c2_1344 = "www.zaigawebinfo.rebatesrule.net" ascii
      $c2_1345 = "www.zebra.incloud-go.com" ascii
      $c2_1346 = "www2.qpoe.com" ascii
      $c2_1347 = "www2.zyns.com" ascii
      $c2_1348 = "www2.zzux.com" ascii
      $c2_1349 = "x7.usyahooapis.com" ascii
      $c2_1350 = "xi.dyndns.pro" ascii
      $c2_1351 = "xi.sexxxy.biz" ascii
      $c2_1352 = "xread10821.9966.org" ascii
      $c2_1353 = "xsince.tk" ascii
      $c2_1354 = "xt.dnset.com" ascii
      $c2_1355 = "xyrn998754.2288.org" ascii
      $c2_1356 = "yahoo.incloud-go.com" ascii
      $c2_1357 = "yallago.cu.cc" ascii
      $c2_1358 = "yandexr.sellclassics.com" ascii
      $c2_1359 = "yeahyeahyeahs.3322.org" ascii
      $c2_1360 = "yeap1.jumpingcrab.com" ascii
      $c2_1361 = "yfrfyhf.youdontcare.com" ascii
      $c2_1362 = "yo.acmetoy.com" ascii
      $c2_1363 = "za.myftp.info" ascii
      $c2_1364 = "zabbix.servercontrols.pw" ascii
      $c2_1365 = "zaigawebinfo.rebatesrule.net" ascii
      $c2_1367 = "zebra.UsFfUnicef.com" ascii
      $c2_1368 = "zebra.bdoncloud.com" ascii
      $c2_1369 = "zebra.incloud-go.com" ascii
      $c2_1370 = "zebra.unhamj.com" ascii
      $c2_1371 = "zebra.wthelpdesk.com" ascii
      $c2_1372 = "zero.pcanywhere.net" ascii
      $c2_1373 = "zg.ns02.biz" ascii
      $c2_1374 = "zone.demoones.com" ascii
   condition:
      1 of ($c2_*)
}

rule baseline_winnti_dropper_x86_libtomcrypt_fns : TAU CN APT {
   meta:
      author = "CarbonBlack Threat Research" // tharuyama
      date = "2019-08-26"
      description = "Designed to catch winnti 4.0 loader and hack tool x86"
      rule_version = 1
      yara_version = "3.8.1"
      confidence = "Prod"
      oriority = "High"
      TLP = "White"
      reference = "https://www.carbonblack.com/2019/09/04/cb-tau-threat-intelligence-notification-winnti-malware-4-0/"
      exemplar_hashes = "0fdcbd59d6ad41dda9ae8bab8fad9d49b1357282027e333f6894c9a92d0333b3"
      sample_md5 = "da3b64ec6468a4ec56f977afb89661b1"

   strings:
      // fn_register_libtomcrypt
      $0x401d20 = { 8B 0D ?? ?? ?? ?? 33 C0 85 C9 }
      $0x401d30 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 83 F8 ?? }
      $0x401d46 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 10 83 F8 ?? }
      $0x401d76 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 1C 83 F8 ?? }
      $0x401dc4 = { 56 57 B9 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? 33 C0 F3 A5 5F C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 5E C3 }
      // fn_decrypt_PE
      $0x401bd0 = { 55 8B EC B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 56 57 85 C0 C7 45 FC ?? ?? ?? ?? }
      $0x401bf4 = { 8B 45 14 85 C0 }
      $0x401bff = { 8B 45 18 85 C0 }
      $0x401c14 = { 8B 7D 08 8D 45 FC 50 57 E8 ?? ?? ?? ?? 8B 75 ?? 83 C4 08 66 }
      $0x401c31 = { 8B 45 0C 85 C0 }
      $0x401c3c = { 8D 4D FC 51 57 E8 ?? ?? ?? ?? 66 8B 55 FC 83 C4 08 66 3B 55 24 }
      $0x401c57 = { 8B 5D 20 85 DB }
      $0x401c62 = { 57 E8 ?? ?? ?? ?? 8B D0 83 C4 04 83 FA ?? }
      $0x401c72 = { B9 ?? ?? ?? ?? 33 C0 8D BD 48 EE FF FF C7 85 44 EE FF FF ?? ?? ?? ?? F3 AB 8B 4D 0C 8D 85 44 EE FF FF 50 6A ?? 81 E6 FF FF 00 00 6A ?? 56 51 53 52 E8 ?? ?? ?? ?? 83 C4 1C 85 C0 }
      $0x401caf = { 8B 45 1C 8B 4D 18 8D 95 44 EE FF FF 52 8B 55 14 50 51 52 E8 ?? ?? ?? ?? 8B F0 8D 85 44 EE FF FF 50 E8 ?? ?? ?? ?? 83 C4 14 8B C6 5F 5E 5B 8B E5 5D C3 }
      $0x401ce1 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
      $0x401ced = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
      $0x401cf9 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
      $0x401d05 = { 5F 5E B8 ?? ?? ?? ?? 5B 8B E5 5D C3 }
      $0x401d16 = { 5F 5E 5B 8B E5 5D C3 }

   condition:
      all of them
}

rule baseline_asp_file {
	meta:
		description = "Laudanum Injector Tools - file file.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "ff5b1a9598735440bdbaa768b524c639e22f53c5"
	strings:
		$s1 = "' *** Written by Tim Medin <tim@counterhack.com>" fullword ascii
		$s2 = "Response.BinaryWrite(stream.Read)" fullword ascii
		$s3 = "Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "set folder = fso.GetFolder(path)" fullword ascii
		$s6 = "Set file = fso.GetFile(filepath)" fullword ascii
	condition:
		uint16(0) == 0x253c and filesize < 30KB and 5 of them
}

rule baseline_php_killnc {
	meta:
		description = "Laudanum Injector Tools - file killnc.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
	strings:
		$s1 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
		$s3 = "<?php echo exec('killall nc');?>" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "<title>Laudanum Kill nc</title>" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "foreach ($allowedIPs as $IP) {" fullword ascii
	condition:
		filesize < 15KB and 4 of them
}

rule baseline_asp_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "8bf1ff6f8edd45e3102be5f8a1fe030752f45613"
	strings:
		$s1 = "<form action=\"shell.asp\" method=\"POST\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "%ComSpec% /c dir" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Set objCmd = wShell.Exec(cmd)" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "Server.ScriptTimeout = 180" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "cmd = Request.Form(\"cmd\")" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "' ***  http://laudanum.secureideas.net" fullword ascii
		$s7 = "Dim wshell, intReturn, strPResult" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 15KB and 4 of them
}

rule baseline_settings {
	meta:
		description = "Laudanum Injector Tools - file settings.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
	strings:
		$s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<li>Reverse Shell - " fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 13KB and all of them
}

rule baseline_asp_proxy {
	meta:
		description = "Laudanum Injector Tools - file proxy.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "51e97040d1737618b1775578a772fa6c5a31afd8"
	strings:
		$s1 = "'response.write \"<br/>  -value:\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "q = q & \"&\" & key & \"=\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "for each i in Split(http.getAllResponseHeaders, vbLf)" fullword ascii
		$s4 = "'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "s = urlscheme & urlhost & urlport & urlpath" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 50KB and all of them
}

rule baseline_APT_Malware_PutterPanda_MsUpdater_1 {
	meta:
		description = "Detects Malware related to PutterPanda - MSUpdater"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "b55072b67543f58c096571c841a560c53d72f01a"
	strings:
		$x0 = "msupdate.exe" fullword wide /* PEStudio Blacklist: strings */ /* score: '20.01' */
		$x1 = "msupdate" fullword wide /* PEStudio Blacklist: strings */ /* score: '13.01' */

		$s1 = "Microsoft Corporation. All rights reserved." fullword wide /* score: '8.04' */
		$s2 = "Automatic Updates" fullword wide /* PEStudio Blacklist: strings */ /* score: '4.98' */ /* Goodware String - occured 22 times */
		$s3 = "VirtualProtectEx" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.93' */ /* Goodware String - occured 68 times */
		$s4 = "Invalid parameter" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.93' */ /* Goodware String - occured 69 times */
		$s5 = "VirtualAllocEx" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.91' */ /* Goodware String - occured 95 times */
		$s6 = "WriteProcessMemory" fullword ascii /* PEStudio Blacklist: strings */ /* score: '4.87' */ /* Goodware String - occured 131 times */
	condition:
		( uint16(0) == 0x5a4d and 1 of ($x*) and 4 of ($s*) ) or
		( 1 of ($x*) and all of ($s*) )
}

rule baseline_Servantshell {
   meta:
      author = "Arbor Networks ASERT Nov 2015"
      description = "Detects Servantshell malware"
      date = "2017-02-02"
      reference = "https://tinyurl.com/jmp7nrs"
      score = 70
   strings:
      $string1 = "SelfDestruction.cpp"
      $string2 = "SvtShell.cpp"
      $string3 = "InitServant"
      $string4 = "DeinitServant"
      $string5 = "CheckDT"
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule baseline_PLEAD_Downloader_Jun18_1 {
   meta:
      description = "Detects PLEAD Downloader"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://blog.jpcert.or.jp/2018/06/plead-downloader-used-by-blacktech.html"
      date = "2018-06-16"
      hash1 = "a26df4f62ada084a596bf0f603691bc9c02024be98abec4a9872f0ff0085f940"
   strings:
      $s1 = "%02d:%02d:%02d" ascii fullword
      $s2 = "%02d-%02d-%02d" ascii fullword
      $s3 = "1111%02d%02d%02d_%02d%02d2222" ascii fullword
      $a1 = "Scanning..." wide fullword
      $a2 = "Checking..." wide fullword
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
            all of ($s*) or
            ( 2 of ($s*) and 1 of ($a*) )
      )
}

rule baseline_apt_hellsing_implantstrings { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab" 
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing implants"
	strings: 
		$mz = "MZ"
		$a1 = "the file uploaded failed !"
		$a2 = "ping 127.0.0.1"
		$b1 = "the file downloaded failed !"
		$b2 = "common.asp"
		$c = "xweber_server.exe" 
		$d = "action="
		$debugpath1 = "d:\\Hellsing\\release\\msger\\" nocase 
		$debugpath2 = "d:\\hellsing\\sys\\xrat\\" nocase 
		$debugpath3 = "D:\\Hellsing\\release\\exe\\" nocase 
		$debugpath4 = "d:\\hellsing\\sys\\xkat\\" nocase 
		$debugpath5 = "e:\\Hellsing\\release\\clare" nocase 
		$debugpath6 = "e:\\Hellsing\\release\\irene\\" nocase 
		$debugpath7 = "d:\\hellsing\\sys\\irene\\" nocase
		$e = "msger_server.dll" 
		$f = "ServiceMain"
	condition:
		($mz at 0) and (all of ($a*)) or (all of ($b*)) or ($c and $d) or (any of ($debugpath*)) or ($e and $f) and filesize < 500000
}

rule baseline_apt_hellsing_installer { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing xweber/msger installers"
	strings: 
		$mz = "MZ"
		$cmd = "cmd.exe /c ping 127.0.0.1 -n 5&cmd.exe /c del /a /f \"%s\""
		$a1 = "xweber_install_uac.exe"
		$a2 = "system32\\cmd.exe" wide
		$a4 = "S11SWFOrVwR9UlpWRVZZWAR0U1aoBHFTUl2oU1Y="
		$a5 = "S11SWFOrVwR9dnFTUgRUVlNHWVdXBFpTVgRdUlpWRVZZWARdUqhZVlpFR1kEUVNSXahTVgRaU1YEUVNSXahTVl1SWwRZValdVFFZUqgQBF1SWlZFVllYBFRTVqg=" 
		$a6 = "7dqm2ODf5N/Y2N/m6+br3dnZpunl44g=" $a7="vd/m7OXd2ai/5u7a59rr7Ki45drcqMPl5t/c5dqIZw=="
		$a8 = "vd/m7OXd2ai/usPl5qjY2uXp69nZqO7l2qjf5u7a59rr7Kjf5tzr2u7n6euo4+Xm39zl2qju5dqo4+Xm39zl2t/m7ajr19vf2OPr39rj5eaZmqbs5OSINjl2tyI"
		$a9 = "C:\\Windows\\System32\\sysprep\\sysprep.exe" wide 
		$a10 = "%SystemRoot%\\system32\\cmd.exe" wide 
		$a11 = "msger_install.dll"
		$a12 = {00 65 78 2E 64 6C 6C 00}
	condition:
		($mz at 0) and ($cmd and (2 of ($a*))) and filesize < 500000
}

rule baseline_apt_hellsing_proxytool { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing proxy testing tool"
	strings: 
		$mz = "MZ"
		$a1 = "PROXY_INFO: automatic proxy url => %s"
		$a2 = "PROXY_INFO: connection type => %d"
		$a3 = "PROXY_INFO: proxy server => %s"
		$a4 = "PROXY_INFO: bypass list => %s"
		$a5 = "InternetQueryOption failed with GetLastError() %d"
		$a6 = "D:\\Hellsing\\release\\exe\\exe\\" nocase
	condition:
		($mz at 0) and (2 of ($a*)) and filesize < 300000
}

rule baseline_apt_hellsing_xkat { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab" copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing xKat tool"
	strings: 
		$mz = "MZ"
		$a1 = "\\Dbgv.sys" $a2="XKAT_BIN" $a3="release sys file error."
		$a4 = "driver_load error. "
		$a5 = "driver_create error."
		$a6 = "delete file:%s error." 
		$a7 = "delete file:%s ok."
		$a8 = "kill pid:%d error."
		$a9 = "kill pid:%d ok."
		$a10 = "-pid-delete"
		$a11 = "kill and delete pid:%d error."
		$a12 = "kill and delete pid:%d ok."
	condition:
		($mz at 0) and (6 of ($a*)) and filesize < 300000
}

rule baseline_apt_hellsing_msgertype2 { 
	meta:
		version = "1.0"
		filetype = "PE"
		author = "Costin Raiu, Kaspersky Lab"
		copyright = "Kaspersky Lab"
		date = "2015-04-07"
		description = "detection for Hellsing msger type 2 implants"
	strings: 
		$mz = "MZ"
		$a1 = "%s\\system\\%d.txt"
		$a2 = "_msger" 
		$a3 = "http://%s/lib/common.asp?action=user_login&uid=%s&lan=%s&host=%s&os=%s&proxy=%s"
		$a4 = "http://%s/data/%s.1000001000" 
		$a5 = "/lib/common.asp?action=user_upload&file="
		$a6 = "%02X-%02X-%02X-%02X-%02X-%02X"
	condition:
		($mz at 0) and (4 of ($a*)) and filesize < 500000
}

rule baseline_RAT_Ap0calypse
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		description = "Detects Ap0calypse RAT"
		date = "01.04.2014"
		reference = "http://malwareconfig.com/stats/Ap0calypse"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Ap0calypse"
		$b = "Sifre"
		$c = "MsgGoster"
		$d = "Baslik"
		$e = "Dosyalars"
		$f = "Injecsiyon"

	condition:
		all of them
}

rule baseline_RAT_Arcom
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Arcom RAT"
		reference = "http://malwareconfig.com/stats/Arcom"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a1 = "CVu3388fnek3W(3ij3fkp0930di"
		$a2 = "ZINGAWI2"
		$a3 = "clWebLightGoldenrodYellow"
		$a4 = "Ancestor for '%s' not found" wide
		$a5 = "Control-C hit" wide
		$a6 = {A3 24 25 21}

	condition:
		all of them
}

rule baseline_RAT_Bandook
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Bandook RAT"
		reference = "http://malwareconfig.com/stats/bandook"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "aaaaaa1|"
		$b = "aaaaaa2|"
		$c = "aaaaaa3|"
		$d = "aaaaaa4|"
		$e = "aaaaaa5|"
		$f = "%s%d.exe"
		$g = "astalavista"
		$h = "givemecache"
		$i = "%s\\system32\\drivers\\blogs\\*"
		$j = "bndk13me"

	condition:
		all of them
}

rule baseline_RAT_BlackNix
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects BlackNix RAT"
		reference = "http://malwareconfig.com/stats/BlackNix"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a1 = "SETTINGS" wide
		$a2 = "Mark Adler"
		$a3 = "Random-Number-Here"
		$a4 = "RemoteShell"
		$a5 = "SystemInfo"

	condition:
		all of them
}

rule baseline_RAT_BlackShades
{
	meta:
		author = "Brian Wallace (@botnet_hunter)"
		date = "01.04.2014"
		description = "Detects BlackShades RAT"
		reference = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
		family = "blackshades"

	strings:
		$string1 = "bss_server"
		$string2 = "txtChat"
		$string3 = "UDPFlood"

	condition:
		all of them
}

rule baseline_RAT_BlueBanana
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects BlueBanana RAT"
		reference = "http://malwareconfig.com/stats/BlueBanana"
		maltype = "Remote Access Trojan"
		filetype = "Java"

	strings:
		$meta = "META-INF"
		$conf = "config.txt"
		$a = "a/a/a/a/f.class"
		$b = "a/a/a/a/l.class"
		$c = "a/a/a/b/q.class"
		$d = "a/a/a/b/v.class"

	condition:
		all of them
}

rule baseline_RAT_Bozok
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Bozok RAT"
		reference = "http://malwareconfig.com/stats/Bozok"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "getVer" nocase
		$b = "StartVNC" nocase
		$c = "SendCamList" nocase
		$d = "untPlugin" nocase
		$e = "gethostbyname" nocase

	condition:
		all of them
}

rule baseline_RAT_ClientMesh
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net> (slightly modified by Florian Roth to improve performance)"
		date = "01.06.2014"
		description = "Detects ClientMesh RAT"
		reference = "http://malwareconfig.com/stats/ClientMesh"
		family = "torct"

	strings:
		$string1 = "machinedetails"
		$string2 = "MySettings"
		$string3 = "sendftppasswords"
		$string4 = "sendbrowserpasswords"
		$string5 = "arma2keyMass"
		$string6 = "keylogger"

	condition:
		all of them
}

rule baseline_RAT_CyberGate
{

	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects CyberGate RAT"
		reference = "http://malwareconfig.com/stats/CyberGate"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string1 = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
		$string2 = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
		$string3 = "EditSvr"
		$string4 = "TLoader"
		$string5 = "Stroks"
		$string6 = "####@####"
		$res1 = "XX-XX-XX-XX"
		$res2 = "CG-CG-CG-CG"

	condition:
		all of ($string*) and any of ($res*)
}

rule baseline_RAT_DarkComet
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects DarkComet RAT"
		reference = "http://malwareconfig.com/stats/DarkComet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		// Versions 2x
		$a1 = "#BOT#URLUpdate"
		$a2 = "Command successfully executed!"
		$a3 = "MUTEXNAME" wide
		$a4 = "NETDATA" wide
		// Versions 3x & 4x & 5x
		$b1 = "FastMM Borland Edition"
		$b2 = "%s, ClassID: %s"
		$b3 = "I wasn't able to open the hosts file"
		$b4 = "#BOT#VisitUrl"
		$b5 = "#KCMDDC"

	condition:
		all of ($a*) or all of ($b*)
}

rule baseline_RAT_PoisonIvy
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects PoisonIvy RAT"
		reference = "http://malwareconfig.com/stats/PoisonIvy"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$stub = {04 08 00 53 74 75 62 50 61 74 68 18 04}
		$string1 = "CONNECT %s:%i HTTP/1.0"
		$string2 = "ws2_32"
		$string3 = "cks=u"
		$string4 = "thj@h"
		$string5 = "advpack"

	condition:
		$stub at 0x1620 and all of ($string*) or (all of them)
}

rule baseline_RAT_PredatorPain
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects PredatorPain RAT"
		reference = "http://malwareconfig.com/stats/PredatorPain"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string1 = "holderwb.txt" wide
		$string3 = "There is a file attached to this email" wide
		$string4 = "screens\\screenshot" wide
		$string5 = "Disablelogger" wide
		$string6 = "\\pidloc.txt" wide
		$string7 = "clearie" wide
		$string8 = "clearff" wide
		$string9 = "emails should be sent to you shortly" wide
		$string10 = "jagex_cache\\regPin" wide
		$string11 = "open=Sys.exe" wide
		$ver1 = "PredatorLogger" wide
		$ver2 = "EncryptedCredentials" wide
		$ver3 = "Predator Pain" wide

	condition:
		7 of ($string*) and any of ($ver*)
}

rule baseline_RAT_Punisher
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Punisher RAT"
		reference = "http://malwareconfig.com/stats/Punisher"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "abccba"
		$b = {5C 00 68 00 66 00 68 00 2E 00 76 00 62 00 73}
		$c = {5C 00 73 00 63 00 2E 00 76 00 62 00 73}
		$d = "SpyTheSpy" wide ascii
		$e = "wireshark" wide
		$f = "apateDNS" wide
		$g = "abccbaDanabccb"

	condition:
		all of them
}

rule baseline_RAT_PythoRAT
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Python RAT"
		reference = "http://malwareconfig.com/stats/PythoRAT"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "TKeylogger"
		$b = "uFileTransfer"
		$c = "TTDownload"
		$d = "SETTINGS"
		$e = "Unknown" wide
		$f = "#@#@#"
		$g = "PluginData"
		$i = "OnPluginMessage"

	condition:
		all of them
}

rule baseline_RAT_QRat
{
	meta:
		author = "Kevin Breen @KevTheHermit"
		date = "01.08.2015"
		description = "Detects QRAT"
		reference = "http://malwareconfig.com"
		maltype = "Remote Access Trojan"
		filetype = "jar"

	strings:
		$a0 = "e-data"
		$a1 = "quaverse/crypter"
		$a2 = "Qrypt.class"
		$a3 = "Jarizer.class"
		$a4 = "URLConnection.class"

	condition:
		4 of them
}

rule baseline_RAT_Sakula
{
	meta:
		date = "2015-10-13"
		description = "Detects Sakula v1.0 RAT"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou / NCC Group David Cannings"
		reference = "http://blog.airbuscybersecurity.com/public/YFR/sakula_v1x.yara"

	strings:
		$s1 = "%d_of_%d_for_%s_on_%s"
		$s2 = "/c ping 127.0.0.1 & del /q \"%s\""
		$s3 = "=%s&type=%d"
		$s4 = "?photoid="
		$s5 = "iexplorer"
		$s6 = "net start \"%s\""
		$s7 = "cmd.exe /c rundll32 \"%s\""

		$v1_1 = "MicroPlayerUpdate.exe"
		$v1_2 = "CCPUpdate"
		$v1_3 = { 81 3E 78 03 00 00 75 57  8D 54 24 14 52 68 0C 05 41 00 68 01 00 00 80 FF  15 00 F0 40 00 85 C0 74 10 8B 44 24 14 68 2C 31  41 00 50 FF 15 10 F0 40 00 8B 4C 24 14 51 FF 15  24 F0 40 00 E8 0F 09 00 }
		$v1_4 = { 50 E8 CD FC FF FF 83 C4  04 68 E8 03 00 00 FF D7 56 E8 54 12 00 00 E9 AE  FE FF FF E8 13 F5 FF FF }

		$serial01 = { 31 06 2e 48 3e 01 06 b1 8c 98 2f 00 53 18 5c 36 }
		$serial02 = { 01 a5 d9 59 95 19 b1 ba fc fa d0 e8 0b 6d 67 35 }
		$serial03 = { 47 d5 d5 37 2b cb 15 62 b4 c9 f4 c2 bd f1 35 87 }
		$serial04 = { 3a c1 0e 68 f1 ce 51 9e 84 dd cd 28 b1 1f a5 42 }

		$opcodes1 = { 89 FF 55 89 E5 83 EC 20 A1 ?? ?? ?? 00 83 F8 00 }
		$opcodes2 = { 31 C0 8A 04 0B 3C 00 74 09 38 D0 74 05 30 D0 88 04 0B }
		$opcodes3 = { 8B 45 08 8D 0C 02 8A 01 84 C0 74 08 3C ?? 74 04 34 ?? 88 01 }
		$opcodes4 = { 30 14 38 8D 0C 38 40 FE C2 3B C6 }
		$opcodes5 = { 30 14 39 8D 04 39 41 FE C2 3B CE }

		$fp1 = "Symantec Corporation" ascii wide
	condition:
		uint16(0) == 0x5a4d and (
			(3 of ($s*) and any of ($v1_*)) or
			(any of ($serial0*)) or
			(any of ($opcodes*))
		)
      and not 1 of ($fp*)
}

rule baseline_RAT_ShadowTech
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects ShadowTech RAT"
		reference = "http://malwareconfig.com/stats/ShadowTech"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		type = "file"
	strings:
		$a = "ShadowTech" nocase
		$b = "DownloadContainer"
		$c = "MySettings"
		$d = "System.Configuration"
		$newline = "#-@NewLine@-#" wide
		$split = "pSIL" wide
		$key = "ESIL" wide

	condition:
		4 of them
}

rule baseline_RAT_SmallNet
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects SmallNet RAT"
		reference = "http://malwareconfig.com/stats/SmallNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$split1 = "!!<3SAFIA<3!!"
		$split2 = "!!ElMattadorDz!!"
		$a1 = "stub_2.Properties"
		$a2 = "stub.exe" wide
		$a3 = "get_CurrentDomain"

	condition:
		($split1 or $split2) and (all of ($a*))
}

rule baseline_RAT_SpyGate
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects SpyGate RAT"
		reference = "http://malwareconfig.com/stats/SpyGate"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$split = "abccba"
		$a1 = "abccbaSpyGateRATabccba" //$a = Version 0.2.6
		$a2 = "StubX.pdb"
		$a3 = "abccbaDanabccb"
		$b1 = "monikerString" nocase //$b = Version 2.0
		$b2 = "virustotal1"
		$b3 = "get_CurrentDomain"
		$c1 = "shutdowncomputer" wide //$c = Version 2.9
		$c2 = "shutdown -r -t 00" wide
		$c3 = "set cdaudio door closed" wide
		$c4 = "FileManagerSplit" wide
		$c5 = "Chating With >> [~Hacker~]" wide

	condition:
		(all of ($a*) and #split > 40) or (all of ($b*) and #split > 10) or (all of ($c*))
}

rule baseline_RAT_Sub7Nation
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net> (slightly modified by Florian Roth to improve performance)"
		date = "01.04.2014"
		description = "Detects Sub7Nation RAT"
		reference = "http://malwareconfig.com/stats/Sub7Nation"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "EnableLUA /t REG_DWORD /d 0 /f"
		$i = "HostSettings"
		$verSpecific1 = "sevane.tmp"
		$verSpecific2 = "cmd_.bat"
		$verSpecific3 = "a2b7c3d7e4"
		$verSpecific4 = "cmd.dll"

	condition:
		all of them
}

rule baseline_Slingshot_APT_Malware_4 {
   meta:
      description = "Detects malware from Slingshot APT"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
      hash1 = "38c4f5320b03cbaf5c14997ea321507730a8c16906e5906cbf458139c91d5945"
   strings:
      $x1 = "Ss -a 4104 -s 257092 -o 8 -l 406016 -r 4096 -z 315440" fullword wide

      $s1 = "Slingshot" fullword ascii
      $s2 = "\\\\?\\e:\\$Recycle.Bin\\" wide
      $s3 = "LineRecs.reloc" fullword ascii
      $s4 = "EXITGNG" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         $x1 or 2 of them
      )
}

rule baseline_Empire_Invoke_BypassUAC {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-BypassUAC.ps1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "ab0f900a6915b7497313977871a64c3658f3e6f73f11b03d2d33ca61305dc6a8"
	strings:
		$s1 = "$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii 
		$s2 = "$proc = Start-Process -WindowStyle Hidden notepad.exe -PassThru" fullword ascii 
		$s3 = "$Payload = Invoke-PatchDll -DllBytes $Payload -FindString \"ExitThread\" -ReplaceString \"ExitProcess\"" fullword ascii 
		$s4 = "$temp = [System.Text.Encoding]::UNICODE.GetBytes($szTempDllPath)" fullword ascii 
	condition:
		filesize < 1200KB and 3 of them
}

rule baseline_Empire_lib_modules_trollsploit_message {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file message.py"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "71f2258177eb16eafabb110a9333faab30edacf67cb019d5eab3c12d095655d5"
	strings:
		$s1 = "script += \" -\" + str(option) + \" \\\"\" + str(values['Value'].strip(\"\\\"\")) + \"\\\"\"" fullword ascii 
		$s2 = "if option.lower() != \"agent\" and option.lower() != \"computername\":" fullword ascii 
		$s3 = "[String] $Title = 'ERROR - 0xA801B720'" fullword ascii 
		$s4 = "'Value'         :   'Lost contact with the Domain Controller.'" fullword ascii 
	condition:
		filesize < 10KB and 3 of them
}

rule baseline_Empire_Persistence {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Persistence.psm1"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "ae8875f7fcb8b4de5cf9721a9f5a9f7782f7c436c86422060ecdc5181e31092f"
	strings:
		$s1 = "C:\\PS>Add-Persistence -ScriptBlock $RickRoll -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -V" ascii 
		$s2 = "# Execute the following to remove the user-level persistent payload" fullword ascii 
		$s3 = "$PersistantScript = $PersistantScript.ToString().Replace('EXECUTEFUNCTION', \"$PersistenceScriptName -Persist\")" fullword ascii 
	condition:
		filesize < 108KB and 1 of them
}

rule baseline_Empire_portscan {
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file portscan.py"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/PowerShellEmpire/Empire"
		date = "2015-08-06"
		score = 70
		hash = "b355efa1e7b3681b1402e22c58ce968795ef245fd08a0afb948d45c173e60b97"
	strings:
		$s1 = "script += \"Invoke-PortScan -noProgressMeter -f\"" fullword ascii 
		$s2 = "script += \" | ? {$_.alive}| Select-Object HostName,@{name='OpenPorts';expression={$_.openPorts -join ','}} | ft -wrap | Out-Str" ascii 
	condition:
		filesize < 14KB and all of them
}

rule bin_wuaus {
	meta:
		description = "Webshells Auto-generated - file wuaus.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "46a365992bec7377b48a2263c49e4e7d"
	strings:
		$s1 = "9(90989@9V9^9f9n9v9"
		$s2 = ":(:,:0:4:8:C:H:N:T:Y:_:e:o:y:"
		$s3 = ";(=@=G=O=T=X=\\="
		$s4 = "TCP Send Error!!"
		$s5 = "1\"1;1X1^1e1m1w1~1"
		$s8 = "=$=)=/=<=Y=_=j=p=z="
	condition:
		all of them
}
