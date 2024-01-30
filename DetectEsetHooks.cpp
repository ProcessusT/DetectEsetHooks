#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <Psapi.h>
#include <string>


// Static functions definitions

/**
* Credits to MALDEVACADEMY
* Compares two strings (case insensitive)
*/
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {
    WCHAR   lStr1[MAX_PATH],
        lStr2[MAX_PATH];

    int		len1 = lstrlenW(Str1),
        len2 = lstrlenW(Str2);

    int		i = 0,
        j = 0;
    // Checking length. We dont want to overflow the buffers
    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;
    // Converting Str1 to lower case string (lStr1)
    for (i = 0; i < len1; i++) {
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[i++] = L'\0'; // null terminating
    // Converting Str2 to lower case string (lStr2)
    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(Str2[j]);
    }
    lStr2[j++] = L'\0'; // null terminating
    // Comparing the lower-case strings
    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;
    return FALSE;
}





/**
* Credits to MALDEVACADEMY
* Retrieves the base address of a module from the PEB
* and enumerates the linked list of modules to find the correct one.
*/
HMODULE CustomGetModuleHandle(IN char szModuleName[]) {
    // convert char to LPCWSTR
    int wideStrLen = MultiByteToWideChar(CP_UTF8, 0, szModuleName, -1, nullptr, 0);
    wchar_t* wideStr = new wchar_t[wideStrLen];
    MultiByteToWideChar(CP_UTF8, 0, szModuleName, -1, wideStr, wideStrLen);
    LPCWSTR lpWideStr = wideStr;
    // Getting PEB
#ifdef _WIN64 // if compiling as x64
    PPEB			pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
    PPEB			pPeb = (PEB*)(__readfsdword(0x30));
#endif// Getting Ldr
    PPEB_LDR_DATA		    pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    // Getting the first element in the linked list which contains information about the first module
    PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
    while (pDte) {
        // If not null
        if (pDte->FullDllName.Length != NULL) {
            // Check if both equal
            //printf("[+] Module name : %ws\n", pDte->FullDllName.Buffer);
            if (IsStringEqual(pDte->FullDllName.Buffer, lpWideStr)) {
                //wprintf(L"[+] Module found from PEB : \"%s\" \n", pDte->FullDllName.Buffer);
                return(HMODULE)pDte->Reserved2[0];
            }
        }
        else {
            break;
        }
        // Next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }
    wprintf(L"[+] Module not found in PEB");
    exit(0);
    return NULL;
}







void main() {

    char _esetdll[] = { 'e','b','e','h','m','o','n','i','.','d','l','l',0 };
	HMODULE hModule = CustomGetModuleHandle(_esetdll);
    printf("\n[+] Find target module name : %s\n", _esetdll);
	printf("[+] Module base address : 0x%p\n", hModule);

    MODULEINFO modInfo;
    modInfo.SizeOfImage = 0;
    GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
    printf("[+] Module size : %d\n", modInfo.SizeOfImage);

    printf("\n[+] Manual reading of module...\n\n");
    BYTE buffer[999999]; // enough to read the whole module
    char buffer2[9999];
    SIZE_T maxBytesToRead = modInfo.SizeOfImage;
    // parsing the whole module
    ReadProcessMemory(GetCurrentProcess(), (LPCVOID)hModule, (LPVOID)buffer, modInfo.SizeOfImage, &maxBytesToRead);
    // recover all printable characters
    int bf2 = 0;
    for (SIZE_T i = 0; i < sizeof(buffer); i++)
    {
        if (buffer[i] >= 0x20 && buffer[i] <= 0x7E)
        {
            buffer2[bf2] = buffer[i];
            bf2++;
        }
    }
    try
    {
        std::string str = buffer2;
        while (true)
        {
            int where = str.find("lambda_1");
            if (where == -1)
            {
				break;
			}
            std::string str2 = str.substr(where + 9, 50).c_str();
            size_t from = str2.find_first_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
            std::string str3 = str2.substr(from + 9, 50).c_str();
            size_t to = str3.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
            std::string func = str2.substr(from, (to + 9)).c_str();
            printf("[+] Hooked function : %s\n", func.c_str());
            str = str.substr(where + 9, sizeof(buffer2)-(where+9));
        }

    }
    catch (const std::exception&)
    {
        printf("[+] End of string parsing\n");
    }

    return;    
}





