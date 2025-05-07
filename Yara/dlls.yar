import "pe"
import "math"


rule KernelImport {

	meta:
        author = "Albu Emanuel Ioan"
	    desc = "Function used for checking if the debugger exists (anti VM malwares)"

		
	condition:
		pe.imports("Kernel32.dll", "IsDebuggerPresent") 
		or pe.imports("kernel32.dll", "CheckRemoteDebuggerPresent")
		or pe.imports("NtDll.dll", "DbgBreakPoint") 
        
}

rule KernelImport2 {

	meta:
        author = "Albu Emanuel Ioan"
	    desc = "Function used for checking if the debugger exists (anti VM malwares)"

		
	condition:
		pe.imports("Advapi32.dll", "AdjustTokenPrivileges")
		or pe.imports("User32.dll", "AttachThreadInput") 
		or pe.imports("Kernel32.dll", "CreateRemoteThread") or  pe.imports("Kernel32.dll", "ReadProcessMemory")   
		or pe.imports("ntdll.dll", "NtWriteVirtualMemory")  or pe.imports("Kernel32.dll", "WriteProcessMemory") 
		or pe.imports("Kernel32.dll", "LoadLibraryExA") or pe.imports("Kernel32.dll", "LoadLibraryExW")     
		or pe.imports("ntdll.dll", "LdrLoadDll")          //  Low-level function to load a DLL into a process
		or pe.imports("Advapi32.dll", "CreateService")  
		or pe.imports("Kernel32.dll", "DeviceIoControl") 
}

rule AdminPrivileges {

	meta:
        author = "Albu Emanuel Ioan"
	    desc = "Checks if the user has administrator privileges"

		
	condition:			
		pe.imports("advpack.dll", "IsNTAdmin") or pe.imports("advpack.dll", "CheckTokenMembership")
        or pe.imports("Shell32.dll", "IsUserAnAdmin ")
}

rule Networking {

	meta:
        author = "Albu Emanuel Ioan"
	    desc = "Networking"

		
	condition:			
		pe.imports("Netapi32.dll", "NetShareEnum") 			// Retrieves information about each shared resource on a server
		or pe.imports("User32.dll", "RegisterHotKey")			// spyware detecting
		or pe.imports("NtosKrnl.exe", "RtlCreateRegistryKey")	// create registry key from the kernel mode		
		or pe.imports("Urlmon.dll", "URLDownloadToFile")
		or pe.imports("Ws2_32.dll", "accept") 
		or pe.imports("User32.dll", "bind") 
}

rule BadImports {

	meta:
        author = "Albu Emanuel Ioan"
	    desc = "General bad import"

		
	condition:			
		pe.imports("Kernel32.dll", "SetFileTime")			// modify the creation and access time of files
		or pe.imports("User32.dll", "SetWindowsHookEx")			//  hook functions
		or pe.imports("Shell32.dll", "ShellExecute") 
		or pe.imports("Shell32.dll", "ShellExecuteExA")
		or pe.imports("Kernel32.dll", "VirtualAllocEx")   
		or pe.imports("kernel32.dll", "VirtualProtectEx") 
		or pe.imports("Kernel32.dll", "WinExec")
        or pe.imports("Advapi32.dll", "CryptEncrypt")
        or pe.imports("ntdll.dll", "NtRaiseHardError ")  
}

rule RootkitDriversFunctions {

	meta:
        author = "Albu Emanuel Ioan"
	    desc = "Rootkit / Drivers / Functions"

		
	condition:			
		pe.imports("NtosKrnl.exe", "NtOpenProcess ")  
		or pe.imports("ntdll.dll", "NtLoadDriver") 
		or pe.imports("sfc_os.exe", "SetSfcFileException ")      // it makes Windows to allow modification of any protected file  
}


