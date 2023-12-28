/*
ModifyExports.cpp
Alsch092 @ github
Last updated: Dec 28 2023
*/

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <ImageHlp.h>
#pragma comment(lib, "ImageHlp")

using namespace std;

void StopDLLInjection();

void __declspec(dllexport) FunctionExportA()
{
	MessageBoxA(0, "Hello from A!", 0, 0);
}

void __declspec(dllexport) FunctionExportB()
{
	MessageBoxA(0, "Hello from B!", 0, 0);
}

bool ModifyExportName(string dllName, string functionName, string newName)
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

int main(void)
{
	ModifyExportName("ModifyExports.exe", "FunctionExportA", "FunctionExportB"); //after this call there will be two `FunctionExportB` exports
	ModifyExportName("ModifyExports.exe", "FunctionExportB", "FunctionExportC"); //and after this call, there will be FunctionExportB and FunctionExportC
	
	HMODULE image = GetModuleHandleW(NULL);

	UINT64 addr_A = (UINT64)GetProcAddress(image, "FunctionExportB"); //example of how we can control code flow through modifying export names: 
	UINT64 addr_B = (UINT64)GetProcAddress(image, "FunctionExportC"); //   -> If some DLL exports "CalledFunctionA" , we can change th
	
	UINT64 old_A = (UINT64)GetProcAddress(image, "FunctionExportA");

	printf("Addr (A): %llX\n", addr_A); //addresses will be updated properly. FunctionExportB is now the address of FunctionExportA
	printf("Addr (B): %llX\n", addr_B); //.. and FunctionExportC is the address of FunctionExportB
	printf("Addr (old A): %llX\n", old_A); //this will return 0, which shows an example of denying availability of an export

	StopDLLInjection();
	return 0;
}

void StopDLLInjection() //prevents DLL injection from any tools that make use of 'LoadLibrary' in the host process. We can expand this idea to break many other functionalities of tools.
{
	ModifyExportName("KERNEL32.DLL", "LoadLibraryA", ""); //KERNEL32.LoadLibraryA jumps to KERNELBASE.LoadLibraryA, so we should write over both of them
	ModifyExportName("KERNEL32.DLL", "LoadLibraryW", "");
	ModifyExportName("KERNEL32.DLL", "LoadLibraryExA", "");
	ModifyExportName("KERNEL32.DLL", "LoadLibraryExW", "");

	ModifyExportName("KERNELBASE.DLL", "LoadLibraryA", ""); //most injectors will write the DLL name into a target process then call createRemoteThread with LoadLibrary's address
	ModifyExportName("KERNELBASE.DLL", "LoadLibraryW", "");
	ModifyExportName("KERNELBASE.DLL", "LoadLibraryExA", "");
	ModifyExportName("KERNELBASE.DLL", "LoadLibraryExW", "");
}

