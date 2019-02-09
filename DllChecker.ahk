/*
	DllChecker.ahk
	Author: Patrick Flöß
	Version: 2019-02-09
*/

DLLChecker:

; DLL files to search for in an array, expandable with comma separation.
Array := ["MSOSVG.dll"]

; DLL SHA512 Checksum for the respective DLL. Please apply the same order of checksums and DLL. 
Array1 := ["505CB31C008EA0E5F4C9E3EA81B76843512CEA9E62BBD71D046C454E7085A653C9CF25674FB9A498B9C33F7F41915E8439DDAAB03624A28E27F37825BA942687"] 

; Hardcoded MSO Paths to search for DLL files. 
Array2 := [A_ProgramFiles "\Microsoft Office\root\Office16\", "C:\Program Files\Microsoft Office\root\Office16\", A_ProgramFiles "\Microsoft Office\root\Office17\", "C:\Program Files\Microsoft Office\root\Office17\", A_ProgramFiles "\Microsoft Office\root\Office18\", "C:\Program Files\Microsoft Office\root\Office18\", A_ScriptDir "`\", A_WinDir "\System32\", A_WinDir "\System\", A_WinDir "`\", A_MyDocuments "`\"]

; Read all HKEY_LOCAL_MACHINE PATHs.
Env_ReadAll("NameArray", "ValueArray")
loop, %NameArray0%
{
	s := NameArray%A_index% . " = " . ValueArray%A_index% . "`r`n"
	If (NameArray%A_index% = "PATH") {
		TextSpeicherHKLM := ValueArray%A_index% 
	}
	Loops++
}

; Read all HKEY_CURRENT_USER PATHs. 
Env_ReadAllCU("NameArray", "ValueArray")
loop, %NameArray0%
{
	s := NameArray%A_index% . " = " . ValueArray%A_index% . "`r`n"
	If (NameArray%A_index% = "PATH") {
		TextSpeicherHKCU := NameArray%A_index%
	}
	Loops++
}

; Combine HKLM and HKCU PATH contents.
TextSpeicherAlle := """" TextSpeicherHKLM ";" TextSpeicherHKCU """"

; Text Transform  ; ==> ,.
TextSpeicherAlle := StrReplace(TextSpeicherAlle, "\;", ";")

; Create array from string for PATH variable. 
ArrayPATH := StrSplit(TextSpeicherAlle, ";")

; Loop through arrays.
Loop % Array.length() 
{
	SuchDatei := Array[A_Index] 
	SuchChecksum := Array1[A_Index]
	; Search for DLL file in each relevant path. 
	Loop % Array2.length() 
	{
		SuchPfad := Array2[A_Index]
		KompletterPfad := SuchPfad SuchDatei
		; If file in "KompletterPfad" exists, calculate the SHA512 checksum.
		IfExist, % KompletterPfad
		{
			; Compare against array of Checksums.
			If (SuchChecksum = HashFile(KompletterPfad,6)) {
				gosub, DllcheckerKeinProb
			} else {
				gosub, DllcheckerProb
			}
		}
	}
	; Search for DLL file in PATH variables.
	Loop % ArrayPATH.length()
	{
		SuchPfad := ArrayPATH[A_Index]
		KompletterPfad := SuchPfad "\" SuchDatei
		; If file in "KompletterPfad" exists, calculate the SHA512 checksum.
		IfExist, % KompletterPfad
		{
			; Compare against array of Checksums.
			If (SuchChecksum = HashFile(KompletterPfad,6)) {
				gosub, DllcheckerKeinProb
			} else {
				gosub, DllcheckerProb
			}
		}
	}
}
MsgBox DLL Prüfung abgeschlossen.
return

DllcheckerKeinProb:
MsgBox Keine Probleme in den DLL Dateien gefunden.
return

DllcheckerProb:
MsgBox % "The file """ SuchDatei """ in the path """ SuchPfad """ does not have the expected SHA512 checksum and may be altered with unwanted source code. Last retreived date of the comparison checksum: February 09, 2019."
; FileAppend, % A_DD "." A_MM "." A_YYYY " " A_Hour ":" A_Min ":" A_Sec " - Findings in:" KompletterPfad, % A_ScriptDir "\DllChecker_Report.txt"
return

; FUNCTIONS
Env_ReadAll(szNameArray, szValueArray)
{
   global
   i := 1
   loop, HKLM, SYSTEM\CurrentControlSet\Control\Session Manager\Environment
   {
      %szNameArray%%i% := A_LoopRegName
      RegRead, %szValueArray%%i%
      i += 1
   }
   %szNameArray%0 := i
   %szValueArray%0 := i
   Return
}

Env_ReadAllCU(szNameArray, szValueArray)
{
   global
   i := 1
   loop, HKCU, Environment
   {
      %szNameArray%%i% := A_LoopRegName
      RegRead, %szValueArray%%i%
      i += 1
   }
   %szNameArray%0 := i
   %szValueArray%0 := i
   Return
}

/*
The below part was written by the user: Deo
Published on: https://autohotkey.com/board/topic/66139-ahk-l-calculating-md5sha-checksum-from-file/
Last accessed: February 5, 2019 
HASH types:
1 - MD2
2 - MD5
3 - SHA
4 - SHA256 - not supported on XP,2000
5 - SHA384 - not supported on XP,2000
6 - SHA512 - not supported on XP,2000
*/
HashFile(filePath,hashType=2)
{
	PROV_RSA_AES := 24
	CRYPT_VERIFYCONTEXT := 0xF0000000
	BUFF_SIZE := 1024 * 1024 ; 1 MB
	HP_HASHVAL := 0x0002
	HP_HASHSIZE := 0x0004
	
	HASH_ALG := hashType = 1 ? (CALG_MD2 := 32769) : HASH_ALG
	HASH_ALG := hashType = 2 ? (CALG_MD5 := 32771) : HASH_ALG
	HASH_ALG := hashType = 3 ? (CALG_SHA := 32772) : HASH_ALG
	HASH_ALG := hashType = 4 ? (CALG_SHA_256 := 32780) : HASH_ALG	;Vista+ only
	HASH_ALG := hashType = 5 ? (CALG_SHA_384 := 32781) : HASH_ALG	;Vista+ only
	HASH_ALG := hashType = 6 ? (CALG_SHA_512 := 32782) : HASH_ALG	;Vista+ only
	
	f := FileOpen(filePath,"r","CP0")
	if !IsObject(f)
		return 0
	if !hModule := DllCall( "GetModuleHandleW", "str", "Advapi32.dll", "Ptr" )
		hModule := DllCall( "LoadLibraryW", "str", "Advapi32.dll", "Ptr" )
	if !dllCall("Advapi32\CryptAcquireContextW"
				,"Ptr*",hCryptProv
				,"Uint",0
				,"Uint",0
				,"Uint",PROV_RSA_AES
				,"UInt",CRYPT_VERIFYCONTEXT )
		Goto,FreeHandles
	
	if !dllCall("Advapi32\CryptCreateHash"
				,"Ptr",hCryptProv
				,"Uint",HASH_ALG
				,"Uint",0
				,"Uint",0
				,"Ptr*",hHash )
		Goto,FreeHandles
	
	VarSetCapacity(read_buf,BUFF_SIZE,0)
	
    hCryptHashData := DllCall("GetProcAddress", "Ptr", hModule, "AStr", "CryptHashData", "Ptr")
	While (cbCount := f.RawRead(read_buf, BUFF_SIZE))
	{
		if (cbCount = 0)
			break
		
		if !dllCall(hCryptHashData
					,"Ptr",hHash
					,"Ptr",&read_buf
					,"Uint",cbCount
					,"Uint",0 )
			Goto,FreeHandles
	}
	
	if !dllCall("Advapi32\CryptGetHashParam"
				,"Ptr",hHash
				,"Uint",HP_HASHSIZE
				,"Uint*",HashLen
				,"Uint*",HashLenSize := 4
				,"UInt",0 ) 
		Goto,FreeHandles
		
	VarSetCapacity(pbHash,HashLen,0)
	if !dllCall("Advapi32\CryptGetHashParam"
				,"Ptr",hHash
				,"Uint",HP_HASHVAL
				,"Ptr",&pbHash
				,"Uint*",HashLen
				,"UInt",0 )
		Goto,FreeHandles	
	
	SetFormat,integer,Hex
	loop,%HashLen%
	{
		num := numget(pbHash,A_index-1,"UChar")
		hashval .= substr((num >> 4),0) . substr((num & 0xf),0)
	}
	SetFormat,integer,D
		
FreeHandles:
	f.Close()
	DllCall("FreeLibrary", "Ptr", hModule)
	dllCall("Advapi32\CryptDestroyHash","Ptr",hHash)
	dllCall("Advapi32\CryptReleaseContext","Ptr",hCryptProv,"UInt",0)
	return hashval
}

return