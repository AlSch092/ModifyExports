/*
ModifyExports.cpp
Alsch092 @ github
*/

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <ImageHlp.h>
#pragma comment(lib, "ImageHlp")

using namespace std;

bool ModifyDLLExportName(string dllName, string functionName, string newName)
{
	DWORD* dNameRVAs(0); //addresses of export names
	_IMAGE_EXPORT_DIRECTORY* ImageExportDirectory;
	unsigned long cDirSize;
	_LOADED_IMAGE LoadedImage;
	string sName;

	if (MapAndLoad(dllName.c_str(), NULL, &LoadedImage, TRUE, TRUE))
	{
		ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

		if (ImageExportDirectory != NULL)
		{
			//load list of function names from DLL, the third parameter is an RVA to the data we want
			dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);

			for (size_t i = 0; i < ImageExportDirectory->NumberOfNames; i++)
			{
				//get RVA 
				sName = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);

				if (strcmp(functionName.c_str(), sName.c_str()) == 0)
				{
					UINT64 funcName_Address = (UINT64)GetModuleHandleA(dllName.c_str()) + dNameRVAs[i]; //get VA From RVA + imagebase
					printf("funcname_addr: %llX\n", funcName_Address);
					DWORD oldProt = 0;

					if (!VirtualProtect((LPVOID)funcName_Address, 1024, PAGE_EXECUTE_READWRITE, &oldProt))
					{
						printf("VirtualProtect failed: %d\n", GetLastError());
						return false;
					}
					else
					{
						strcpy_s((char*)funcName_Address, 100, newName.c_str());
						printf("Copied over export function name..\n");
					}
				}
			}
		}
		else
		{
			printf("[ERROR] ImageExportDirectory was NULL!\n");
			UnMapAndLoad(&LoadedImage);
			return false;
		}
	}
	else
	{
		printf("MapAndLoad failed: %d\n", GetLastError());
		return false;
	}

	UnMapAndLoad(&LoadedImage);

	return true;
}

//Added on June 29 2023
void StopDLLInjection() //prevents DLL injection from any tools that make use of 'LoadLibrary' in the host process. We can expand this idea to break many other functionalities of tools.
{
	LoadLibrary(L"KERNEL32.dll");
	ModifyDLLExportName("KERNEL32.DLL", "LoadLibraryA", "1");
	ModifyDLLExportName("KERNEL32.DLL", "LoadLibraryW", "2");
	ModifyDLLExportName("KERNEL32.DLL", "LoadLibraryExA", "3");
	ModifyDLLExportName("KERNEL32.DLL", "LoadLibraryExW", "4");
}


int main(void)
{
	StopDLLInjection();
	
	LoadLibrary(L"USER32.dll");

	HMODULE user32 = GetModuleHandleW(L"USER32.dll");

	if (!user32)
	{
		printf("Could not find user32.dll: %d\n", GetLastError());
		return 0;
	}

	UINT64 MsgBoxW = (UINT64)GetProcAddress(user32, "MessageBoxW");

	if (MsgBoxW == NULL) {
		printf("GetProcAddress failed!\n");
		return 0;
	}

	printf("MessageBoxW: %llX\n", (UINT64)MsgBoxW);

	ModifyDLLExportName("USER32.DLL", "MessageBoxW", "MessageBoxX"); //now we have two MessageBoxW symbols
	
	HMODULE program = GetModuleHandleW(L"USER32.dll");

	if (program)
	{
		UINT64 addr_W = (UINT64)GetProcAddress(program, "MessageBoxX"); //we call GetProcAddress again, which now returns 0
		printf("New MessageBoxW: %llX\n", addr_W);
	}

	return 0;
}
