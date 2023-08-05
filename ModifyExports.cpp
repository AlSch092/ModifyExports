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

//prevents DLL injection from any code that makes use of 'LoadLibrary' in the host process. We can expand this idea to break many other functionalities of tools.
//remember that making undocumented changes can decrease the stability of your program, always make sure the tradeoff is worth it
//one downside is that LoadLibrary will likely have the same address across different processes on the same machine.. but regardless, new modules wont be able to load
void StopDLLInjection()
{
	ModifyDLLExportName("KERNEL32.DLL", "LoadLibraryA", ""); //KERNEL32.LoadLibraryA jumps to KERNELBASE.LoadLibraryA, so we should write over both of them
	ModifyDLLExportName("KERNEL32.DLL", "LoadLibraryW", "");
	ModifyDLLExportName("KERNEL32.DLL", "LoadLibraryExA", "");
	ModifyDLLExportName("KERNEL32.DLL", "LoadLibraryExW", "");

	ModifyDLLExportName("KERNELBASE.DLL", "LoadLibraryA", ""); //most injectors will write the DLL name into a target process then call createRemoteThread with LoadLibrary's address
	ModifyDLLExportName("KERNELBASE.DLL", "LoadLibraryW", "");
	ModifyDLLExportName("KERNELBASE.DLL", "LoadLibraryExA", "");
	ModifyDLLExportName("KERNELBASE.DLL", "LoadLibraryExW", "");
}


int main(void)
{
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

	StopDLLInjection();

	return 0;
}

