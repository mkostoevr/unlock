#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define FILE_LINE "(" __FILE__ ": " STR(__LINE__) ")"

VOID Error(LPCSTR szErrorLocation);
VOID FatalError(LPCSTR szErrorLocation);
VOID LowLevelError(LPCSTR szErrorLocation);
VOID FatalLowLevelError(LPCSTR szErrorLocation);

#define LOCAL_ERR_noError "No error?"
#define LOCAL_ERR_errorNumber "Error "
#define LOCAL_ERR_atLocation " in "
#define LOCAL_ERR_moreInfo ". More info:\n"

static LPSTR GetErrorString(DWORD dwErrorCode) {
  LPSTR szErrorString;
  LPSTR szErrorStringBuffer;
  DWORD dwErrorStringBufferSize;
  HLOCAL hFreeResult;

  if (dwErrorCode == 0) {
    szErrorString = HeapAlloc(GetProcessHeap(), 0, sizeof(LOCAL_ERR_noError));
    if (szErrorString == NULL) {
      FatalLowLevelError(FILE_LINE);
    }
    strcpy(szErrorString, LOCAL_ERR_noError);
    return szErrorString;
  }
  dwErrorStringBufferSize = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, dwErrorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPSTR)&szErrorStringBuffer, 0, NULL);
  if (dwErrorStringBufferSize == 0) {
    FatalLowLevelError(FILE_LINE);
  }
  szErrorString = HeapAlloc(GetProcessHeap(), 0, dwErrorStringBufferSize + 1);
  if (szErrorString == NULL) {
    FatalLowLevelError(FILE_LINE);
  }
  strcpy(szErrorString, szErrorStringBuffer);
  hFreeResult = LocalFree(szErrorStringBuffer);
  if (hFreeResult == szErrorStringBuffer) {
    LowLevelError(FILE_LINE);
  }
  return szErrorString;
}

static LPSTR CreateErrorMessage(DWORD dwErrorCode, LPCSTR szErrorLocation) {
  CHAR szErrorCode[11];
  LPSTR szErrorInfo;
  SIZE_T bcMessage;
  LPSTR szMessage;
  BOOL bFreeResult;

  sprintf(szErrorCode, "0x%08lX", dwErrorCode);
  szErrorInfo = GetErrorString(dwErrorCode);
  bcMessage = sizeof(LOCAL_ERR_errorNumber) -
              1 // -1 cause sizeof counts terminating null
              + sizeof(szErrorCode) - 1 + sizeof(LOCAL_ERR_atLocation) - 1 +
              strlen(szErrorLocation) + sizeof(LOCAL_ERR_moreInfo) - 1 +
              strlen(szErrorInfo) + 1; // one more byte for terminating null
  szMessage = HeapAlloc(GetProcessHeap(), 0, bcMessage);
  if (szMessage == NULL) {
    FatalLowLevelError(FILE_LINE);
  }
  strcpy(szMessage, LOCAL_ERR_errorNumber);
  strcat(szMessage, szErrorCode);
  strcat(szMessage, LOCAL_ERR_atLocation);
  strcat(szMessage, szErrorLocation);
  strcat(szMessage, LOCAL_ERR_moreInfo);
  strcat(szMessage, szErrorInfo);
  bFreeResult = HeapFree(GetProcessHeap(), 0, szErrorInfo);
  if (!bFreeResult) {
    LowLevelError(FILE_LINE);
  }
  return szMessage;
}

VOID Error(LPCSTR szErrorLocation) {
  DWORD dwErrorCode;
  LPSTR szErrorMessage;

  dwErrorCode = GetLastError();
  szErrorMessage = CreateErrorMessage(dwErrorCode, szErrorLocation);
  MessageBoxA(NULL, szErrorMessage, NULL, MB_ICONERROR | MB_OK);
  HeapFree(GetProcessHeap(), 0, szErrorMessage);
}

VOID FatalError(LPCSTR szErrorLocation) {
  Error(szErrorLocation);
  ExitProcess(-1);
}

VOID LowLevelError(LPCSTR szErrorLocation) {
  DWORD dwErrorCode;
  CHAR szErrorCode[11];

  dwErrorCode = GetLastError();
  sprintf(szErrorCode, "0x%08lX", dwErrorCode);
  MessageBoxA(0, szErrorCode, szErrorLocation, MB_ICONERROR | MB_OK);
}

VOID FatalLowLevelError(LPCSTR szErrorLocation) {
  LowLevelError(szErrorLocation);
  ExitProcess(-1);
}
