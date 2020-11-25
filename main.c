// Copyright (C) 2008 The Android Open Source Project
// Copyright (C) 2020 Magomed Kostoev

// Compile using:
// clang main.c error.c -luser32 -lntdll -Wno-everything

#ifndef UNICODE
#define UNICODE
#endif

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define FILE_LINE "(" __FILE__ ": " STR(__LINE__) ")"

#include <stdio.h>
#include <windows.h>

#define CDICT_INST
#include "cdict/cdict.h"

//
// Undocumented declarations and other utilities for windows API
//

typedef LONG NTSTATUS;

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE {
  ULONG ProcessId;
  BYTE ObjectTypeNumber;
  BYTE Flags;
  USHORT Handle;
  PVOID Object;
  ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
  ULONG HandleCount;
  SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
  NonPagedPool,
  PagedPool,
  NonPagedPoolMustSucceed,
  DontUseThisType,
  NonPagedPoolCacheAligned,
  PagedPoolCacheAligned,
  NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
  UNICODE_STRING Name;
  ULONG TotalNumberOfObjects;
  ULONG TotalNumberOfHandles;
  ULONG TotalPagedPoolUsage;
  ULONG TotalNonPagedPoolUsage;
  ULONG TotalNamePoolUsage;
  ULONG TotalHandleTableUsage;
  ULONG HighWaterNumberOfObjects;
  ULONG HighWaterNumberOfHandles;
  ULONG HighWaterPagedPoolUsage;
  ULONG HighWaterNonPagedPoolUsage;
  ULONG HighWaterNamePoolUsage;
  ULONG HighWaterHandleTableUsage;
  ULONG InvalidAttributes;
  GENERIC_MAPPING GenericMapping;
  ULONG ValidAccess;
  BOOLEAN SecurityRequired;
  BOOLEAN MaintainHandleCount;
  USHORT MaintainTypeList;
  POOL_TYPE PoolType;
  ULONG PagedPoolUsage;
  ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(HANDLE SourceProcessHandle,
                                            HANDLE SourceHandle,
                                            HANDLE TargetProcessHandle,
                                            PHANDLE TargetHandle,
                                            ACCESS_MASK DesiredAccess,
                                            ULONG Attributes, ULONG Options);
typedef NTSTATUS(NTAPI *_NtQueryObject)(HANDLE ObjectHandle,
                                        ULONG ObjectInformationClass,
                                        PVOID ObjectInformation,
                                        ULONG ObjectInformationLength,
                                        PULONG ReturnLength);

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName) {
  return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

//
// Other utilities
//

// https://android.googlesource.com/platform/bionic/+/ics-mr0/libc/string/memmem.c
void *memmem(const void *haystack, size_t n, const void *needle, size_t m) {
  if (m > n || !m || !n)
    return NULL;
  if (__builtin_expect((m > 1), 1)) {
    const unsigned char *y = (const unsigned char *)haystack;
    const unsigned char *x = (const unsigned char *)needle;
    size_t j = 0;
    size_t k = 1, l = 2;
    if (x[0] == x[1]) {
      k = 2;
      l = 1;
    }
    while (j <= n - m) {
      if (x[1] != y[j + 1]) {
        j += k;
      } else {
        if (!memcmp(x + 2, y + j + 2, m - 2) && x[0] == y[j])
          return (void *)&y[j];
        j += l;
      }
    }
  } else {
    // degenerate case
    return memchr(haystack, ((unsigned char *)needle)[0], n);
  }
  return NULL;
}

char i2hex(int i) {
  if (i > 15) {
    return '0';
  }
  if (i < 10) {
    return '0' + i;
  }
  return 'a' + (i - 10);
}

char *wcs2hex(WCHAR *s) {
  char *res = calloc(sizeof(*s) * 2, wcslen(s) + 1);
  size_t j = 0;
  for (size_t i = 0; i < wcslen(s); i++) {
    res[j++] = i2hex(((s[i] & 0x000f) >> 0));
    res[j++] = i2hex(((s[i] & 0x00f0) >> 4));
    res[j++] = i2hex(((s[i] & 0x0f00) >> 8));
    res[j++] = i2hex(((s[i] & 0xf000) >> 16));
  }
  return res;
}

//
// The code (and data)
//

CDict_CStr_CStr path_to_device;
WCHAR *current_device;

void DisplayVolumePaths(PWCHAR VolumeName) {
  DWORD CharCount = MAX_PATH + 1;
  PWCHAR Names = NULL;
  PWCHAR NameIdx = NULL;
  BOOL Success = FALSE;

  for (;;) {
    //  Allocate a buffer to hold the paths.
    Names = (PWCHAR)calloc(CharCount, sizeof(WCHAR));

    if (!Names) {
      //  If memory can't be allocated, return.
      return;
    }

    //  Obtain all of the paths
    //  for this volume.
    Success = GetVolumePathNamesForVolumeNameW(VolumeName, Names, CharCount,
                                               &CharCount);

    if (Success) {
      break;
    }

    if (GetLastError() != ERROR_MORE_DATA) {
      break;
    }

    //  Try again with the
    //  new suggested size.
    free(Names);
    Names = NULL;
  }

  if (Success) {
    //  Display the various paths.
    for (NameIdx = Names; NameIdx[0] != L'\0'; NameIdx += wcslen(NameIdx) + 1) {
      WCHAR c = NameIdx[wcslen(NameIdx) - 1];
      NameIdx[wcslen(NameIdx) - 1] = 0;
      char *path_to_device_path = wcs2hex(NameIdx);
      char *path_to_device_device = wcs2hex(current_device);
      cdict_CStr_CStr_add_vv(&path_to_device, path_to_device_path,
                             path_to_device_device, CDICT_REPLACE_EXIST);
      NameIdx[wcslen(NameIdx) - 1] = c;
    }
  }

  if (Names != NULL) {
    free(Names);
    Names = NULL;
  }

  return;
}

void fill_path_to_device_dict(void) {
  DWORD CharCount = 0;
  WCHAR DeviceName[MAX_PATH] = L"";
  DWORD Error = ERROR_SUCCESS;
  HANDLE FindHandle = INVALID_HANDLE_VALUE;
  BOOL Found = FALSE;
  size_t Index = 0;
  BOOL Success = FALSE;
  WCHAR VolumeName[MAX_PATH] = L"";

  //  Enumerate all volumes in the system.
  FindHandle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));

  if (FindHandle == INVALID_HANDLE_VALUE) {
    Error = GetLastError();
    wprintf(L"FindFirstVolumeW failed with error code %d\n", Error);
    return;
  }

  for (;;) {
    //  Skip the \\?\ prefix and remove the trailing backslash.
    Index = wcslen(VolumeName) - 1;

    if (VolumeName[0] != L'\\' || VolumeName[1] != L'\\' ||
        VolumeName[2] != L'?' || VolumeName[3] != L'\\' ||
        VolumeName[Index] != L'\\') {
      Error = ERROR_BAD_PATHNAME;
      wprintf(L"FindFirstVolumeW/FindNextVolumeW returned a bad path: %s\n",
              VolumeName);
      break;
    }

    //  QueryDosDeviceW does not allow a trailing backslash,
    //  so temporarily remove it.
    VolumeName[Index] = L'\0';

    CharCount =
        QueryDosDeviceW(&VolumeName[4], DeviceName, ARRAYSIZE(DeviceName));

    VolumeName[Index] = L'\\';

    if (CharCount == 0) {
      Error = GetLastError();
      wprintf(L"QueryDosDeviceW failed with error code %d\n", Error);
      break;
    }

    current_device = DeviceName;
    DisplayVolumePaths(VolumeName);

    //  Move on to the next volume.
    Success = FindNextVolumeW(FindHandle, VolumeName, ARRAYSIZE(VolumeName));

    if (!Success) {
      Error = GetLastError();

      if (Error != ERROR_NO_MORE_FILES) {
        wprintf(L"FindNextVolumeW failed with error code %d\n", Error);
        break;
      }

      //  Finished iterating
      //  through all the volumes.
      Error = ERROR_SUCCESS;
      break;
    }
  }

  FindVolumeClose(FindHandle);
  FindHandle = INVALID_HANDLE_VALUE;
}

int wmain(int argc, WCHAR *argv[]) {
  _NtQuerySystemInformation NtQuerySystemInformation =
      GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
  _NtDuplicateObject NtDuplicateObject =
      GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
  _NtQueryObject NtQueryObject =
      GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
  NTSTATUS status;
  PSYSTEM_HANDLE_INFORMATION handleInfo;
  ULONG handleInfoSize = 0x10000;
  ULONG i;

  cdict_CStr_CStr_init(&path_to_device);

  fill_path_to_device_dict();

  if (argc < 2) {
    printf("Usage:\n%S <filename>\n", argv[0]);
    return 1;
  }

  WCHAR *disk = wcschr(argv[1], L'\\');
  if (!disk) {
    MessageBoxA(0, "Relative path isn't implemented", 0, 0);
    return 0;
  }

  *disk = L'\0';
  WCHAR *disk_path = argv[1];
  char *disk_path_hex = wcs2hex(disk_path);
  char *device_volume_hex =
      cdict_CStr_CStr_get_v(&path_to_device, disk_path_hex);
  *disk = L'\\';
  char *path_hex = wcs2hex(disk);
  char *full_path_hex = calloc(
      sizeof(*full_path_hex), strlen(device_volume_hex) + strlen(path_hex) + 1);
  strcpy(full_path_hex, device_volume_hex);
  strcat(full_path_hex, path_hex);

  handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

  // NtQuerySystemInformation won't give us the correct buffer size,
  // so we guess by doubling the buffer size.
  while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo,
                                            handleInfoSize, NULL)) ==
         STATUS_INFO_LENGTH_MISMATCH)
    handleInfo =
        (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

  // NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
  if (!NT_SUCCESS(status)) {
    printf("NtQuerySystemInformation failed!\n");
    FatalError(FILE_LINE);
    return 1;
  }

  for (i = 0; i < handleInfo->HandleCount; i++) {
    SYSTEM_HANDLE handle = handleInfo->Handles[i];
    HANDLE dupHandle = NULL;
    POBJECT_TYPE_INFORMATION objectTypeInfo;
    PVOID objectNameInfo;
    UNICODE_STRING objectName;
    ULONG returnLength;

    // Duplicate the handle so we can query it.
    if (!NT_SUCCESS(
            (status = NtDuplicateObject(
                 OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId),
                 handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))) {
      continue;
    }

    // Query the object type.
    objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
    if (!NT_SUCCESS((status = NtQueryObject(dupHandle, ObjectTypeInformation,
                                            objectTypeInfo, 0x1000, NULL)))) {
      CloseHandle(dupHandle);
      continue;
    }

    // Query the object name (unless it has an access of
    // 0x0012019f or 0x001A019F, on which NtQueryObject could hang.
    if (handle.GrantedAccess == 0x0012019f ||
        handle.GrantedAccess == 0x001A019F ||
        handle.GrantedAccess == 0x00120189 ||
        handle.GrantedAccess == 0x001f01ff ||
        handle.GrantedAccess == 0x00120089 ||
        handle.GrantedAccess == 0x001A0089) {
      free(objectTypeInfo);
      CloseHandle(dupHandle);
      continue;
    }

    objectNameInfo = malloc(0x1000);
    if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation,
                                  objectNameInfo, 0x1000, &returnLength))) {
      objectNameInfo = realloc(objectNameInfo, returnLength);
      if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation,
                                    objectNameInfo, returnLength, NULL))) {
        free(objectTypeInfo);
        free(objectNameInfo);
        CloseHandle(dupHandle);
        continue;
      }
    }

    objectName = *(PUNICODE_STRING)objectNameInfo;

    if (!wcscmp(objectTypeInfo->Name.Buffer, L"File")) {
      if (objectName.Length) {
        WCHAR *name = calloc(objectName.Length, sizeof(*objectName.Buffer));
        memcpy(name, objectName.Buffer, objectName.Length);
        char *name_hex = wcs2hex(name);
        if (!strncmp(name_hex, full_path_hex, strlen(full_path_hex))) {
          printf("[%#x] \"%.*S\": \"%.*S\" (PID: %u)\n", handle.Handle,
                 objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer,
                 objectName.Length / 2, objectName.Buffer, handle.ProcessId);
          CloseHandle(dupHandle);
          if (!NT_SUCCESS(
                  (status = NtDuplicateObject(
                       OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId),
                       handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0,
                       DUPLICATE_CLOSE_SOURCE)))) {
            printf("[%#x] Error %p (dub close)\n", handle.Handle, status);
            continue;
          }
        }
      }
    }

    free(objectTypeInfo);
    free(objectNameInfo);
    CloseHandle(dupHandle);
  }

  free(handleInfo);

  return 0;
}