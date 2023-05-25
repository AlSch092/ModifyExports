/*
ModifyExports.cpp
Alsch092 @ github
*/

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <format>
#include <ImageHlp.h>
#pragma comment(lib, "ImageHlp")

#include "ModifyExprots.hpp"

#ifdef _DEBUG
#define DCOUT std::cout 
#define DCERR std::cerr
#else
#define DCOUT 0 && std::cout
#define DCERR 0 && std::cerr
#endif

bool modify_exports::ModifyDLLExportName(std::string_view dllName, std::string_view functionName, std::string_view newName)
{
	DWORD* dNameRVAs(0); //addresses of export names
	_IMAGE_EXPORT_DIRECTORY* ImageExportDirectory;
	unsigned long cDirSize;
	_LOADED_IMAGE LoadedImage {};
	std::string sName;

	if (!MapAndLoad(dllName.data(), NULL, &LoadedImage, TRUE, TRUE)) {
		DCERR << "MapAndLoad failed: " << std::hex << GetLastError() << std::endl;
		return false;
	}

	ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);
	if (ImageExportDirectory == NULL) {
		DCERR << "ImageDirectoryEntryToData failed: " << std::hex << GetLastError() << std::endl;
		UnMapAndLoad(&LoadedImage);
		return false;
	}

	dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, 
			ImageExportDirectory->AddressOfNames, NULL);

	for (auto i = 0; i < ImageExportDirectory->NumberOfNames; i++)
	{
		auto rva = dNameRVAs[i];
		sName = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, rva, NULL);
		if (functionName == sName)
		{
			auto funcName_Address = (UINT64)GetModuleHandleA(dllName.data()) + rva; //get VA From RVA + imagebase
			DCOUT << "funcname_addr:" << std::hex << funcName_Address << std::endl;
			
			if (DWORD oldProt = 0; 
				!VirtualProtect((LPVOID)funcName_Address, 1024, PAGE_EXECUTE_READWRITE, &oldProt))
			{
				std::cerr << "VirtualProtect failed: " << std::hex << GetLastError() << std::endl;
				return false;
			}
			else
			{
				strcpy_s((char*)funcName_Address, 100, newName.data());
				DCERR << "Copied over export function name.." << std::endl;
			}
		}
	}
	UnMapAndLoad(&LoadedImage);

	return true;
}