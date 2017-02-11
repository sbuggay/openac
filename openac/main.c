#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string.h>

#include "md5.h"


#define PROCESS_NAME "csgo.exe"

int main(int argc, char *argv[]) {

	boolean processFound = FALSE;

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE) {
		while (Process32Next(snapshot, &entry) == TRUE) {
			if (strcmp(entry.szExeFile, PROCESS_NAME) == 0) {
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);

				if (NULL == hProcess)
					return 1;

				HMODULE hMods[1024];
				DWORD cbNeeded;

				// Get a list of all the modules in this process.
				if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
					for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
						TCHAR modFileName[MAX_PATH];
						if (GetModuleBaseName(hProcess, hMods[i], modFileName, sizeof(modFileName) / sizeof(TCHAR))) {
							printf_s("%s (0x%08X)\n", modFileName, hMods[i]);
						}

						TCHAR modFilePath[MAX_PATH];
						if (GetModuleFileNameEx(hProcess, hMods[i], modFilePath, sizeof(modFilePath) / sizeof(TCHAR))) {
							FILE *file;
							fopen_s(&file, modFilePath, "rb");
							fseek(file, 0, SEEK_END);
							long fsize = ftell(file);
							rewind(file);
							char *data = malloc(fsize + 1);
							fread(data, fsize, 1, file);
							fclose(file);
							printf_s("%ld\n", fsize);
							
							MD5_CTX ctx;
							MD5_Init(&ctx);
							MD5_Update(&ctx, data, fsize);
							
							char *buffer[4];
							MD5_Final(buffer, &ctx);
							printf_s("%x\n", buffer);
							free(data);
						}
					}
				}

				CloseHandle(hProcess);
				processFound = TRUE;
			}
		}
	}

	if (!processFound) {
		printf_s(PROCESS_NAME);
		printf_s(" not found\n");
	}

	CloseHandle(snapshot);

	fgetc(stdin);
	return 0;
}
