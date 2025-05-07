import "pe"
import "math"


rule elte_ImportTableMaliciousFunction {

	meta:
        author = "Rachid AZGAOU - ELTE 2019"
	    desc = "Checking [malicious] functions : registry , process injection , remote connection, keyboard hook.."

		
	condition:
			// function used for checking if the debugger exists (anti VM malwares) 
		pe.imports("Kernel32.dll", "IsDebuggerPresent") 
		or pe.imports("kernel32.dll", "CheckRemoteDebuggerPresent")
		or pe.imports("NtDll.dll", "DbgBreakPoint") 
		
		or pe.imports("Advapi32.dll", "AdjustTokenPrivileges")
		or pe.imports("User32.dll", "AttachThreadInput") 
		or pe.imports("Kernel32.dll", "CreateRemoteThread") or  pe.imports("Kernel32.dll", "ReadProcessMemory")   
		or pe.imports("ntdll.dll", "NtWriteVirtualMemory")  or pe.imports("Kernel32.dll", "WriteProcessMemory") 
		or pe.imports("Kernel32.dll", "LoadLibraryExA") or pe.imports("Kernel32.dll", "LoadLibraryExW")     
		or pe.imports("ntdll.dll", "LdrLoadDll")          //  Low-level function to load a DLL into a process
		or pe.imports("Advapi32.dll", "CreateService")  
		or pe.imports("Kernel32.dll", "DeviceIoControl") 
			
			// checks if the user has administrator privileges			
		or pe.imports("advpack.dll", "IsNTAdmin") or pe.imports("advpack.dll", "CheckTokenMembership") or
		pe.imports("Shell32.dll", "IsUserAnAdmin ")
		
			
			// networking
		or pe.imports("Netapi32.dll", "NetShareEnum") 			// Retrieves information about each shared resource on a server
		or pe.imports("User32.dll", "RegisterHotKey")			// spyware detecting
		or pe.imports("NtosKrnl.exe", "RtlCreateRegistryKey")	// create registry key from the kernel mode		
		or pe.imports("Urlmon.dll", "URLDownloadToFile")
		or pe.imports("Ws2_32.dll", "accept") 
		or pe.imports("User32.dll", "bind") 
		  
		or pe.imports("Kernel32.dll", "SetFileTime")			// modify the creation and access time of files
		or pe.imports("User32.dll", "SetWindowsHookEx")			//  hook functions
		or pe.imports("Shell32.dll", "ShellExecute") 
		or pe.imports("Shell32.dll", "ShellExecuteExA")
		or pe.imports("Kernel32.dll", "VirtualAllocEx")   
		or pe.imports("kernel32.dll", "VirtualProtectEx") 
		or pe.imports("Kernel32.dll", "WinExec") 
		
		or pe.imports("Advapi32.dll", "CryptEncrypt") 
			// Rootkit , drivers (kernel mode) functions
		or pe.imports("NtosKrnl.exe", "NtOpenProcess ")  
		or pe.imports("ntdll.dll", "NtLoadDriver") 
		or pe.imports("sfc_os.exe", "SetSfcFileException ")      // it makes Windows to allow modification of any protected file 
		
		or pe.imports("ntdll.dll", "NtRaiseHardError ")          //  causes a bluescreen of death
		
		 
		 
}