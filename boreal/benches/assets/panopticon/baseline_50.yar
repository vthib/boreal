import "math"

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

