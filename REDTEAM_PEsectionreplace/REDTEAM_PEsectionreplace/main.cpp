#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include <psapi.h>

typedef struct _InPeConfig {
	PVOID base;
	PIMAGE_DOS_HEADER		pDosHdr;
	PIMAGE_NT_HEADERS		pNtHdr;
	PIMAGE_SECTION_HEADER	pSecHdr;
	
	PIMAGE_DATA_DIRECTORY   resource_directory;
	PIMAGE_SECTION_HEADER   resource_section_hdr;
	//PIMAGE_RESOURCE_DIRECTORY pResourceDir;
} InPeConfig, * PInPeConfig;

PVOID get_file(const char* filename, size_t* ret_size) {

	FILE* file = NULL;
	fopen_s(&file, filename, "rb");
	if (file == NULL) {
		return NULL;
	}
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);
	PVOID pe_mem = calloc(1, size);
	if (pe_mem == NULL)
	{
		printf("err pemem\n");
		exit(1);
	}
	fread(pe_mem, size, 1, file);
	fclose(file);
	*ret_size = size;
	return pe_mem;
}

ULONG_PTR get_fileOffset_from_RVA(PInPeConfig _Pe, ULONG_PTR RVA) {
	for (int i = 0; i < _Pe->pNtHdr->FileHeader.NumberOfSections; i++) {
		ULONG_PTR start_offset = _Pe->pSecHdr[i].PointerToRawData;
		ULONG_PTR start_va = _Pe->pSecHdr[i].VirtualAddress;
		ULONG_PTR end = start_va + _Pe->pSecHdr[i].SizeOfRawData;

		if (RVA >= start_va && RVA < end) {
			printf("%s\n", _Pe->pSecHdr[i].Name);
			ULONG_PTR diff = RVA - start_va;
			ULONG_PTR offset = start_offset + diff;
			return offset;
		}
	}
}

int get_sectionoffset_from_RVA(PInPeConfig _Pe, ULONG_PTR RVA) {
	for (int i = 0; i < _Pe->pNtHdr->FileHeader.NumberOfSections; i++) {
		ULONG_PTR start_va = _Pe->pSecHdr[i].VirtualAddress;
		ULONG_PTR end = start_va + _Pe->pSecHdr[i].SizeOfRawData;

		if (RVA >= start_va && RVA < end) {
			return i;
		}
	}
}


void _InitPeStruct(PInPeConfig _Pe, PVOID pPeAddress) {
	_Pe->base = pPeAddress;

	_Pe->pDosHdr = (PIMAGE_DOS_HEADER)pPeAddress;
	_Pe->pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pPeAddress + _Pe->pDosHdr->e_lfanew);
	_Pe->pSecHdr = (PIMAGE_SECTION_HEADER)((SIZE_T)_Pe->pNtHdr + sizeof(IMAGE_NT_HEADERS));

	_Pe->resource_directory = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	//_Pe->pResourceDir = (PIMAGE_RESOURCE_DIRECTORY)((BYTE*)pPeAddress + get_fileOffset_from_RVA(_Pe, _Pe->resource_directory->VirtualAddress));
	_Pe->resource_section_hdr = &_Pe->pSecHdr[get_sectionoffset_from_RVA(_Pe,_Pe->resource_directory->VirtualAddress)];
}

void check_collision(PInPeConfig _Pe)
{
	for (int i = 0; i < _Pe->pNtHdr->FileHeader.NumberOfSections - 1; i++) {
		for (int j = i + 1; j < _Pe->pNtHdr->FileHeader.NumberOfSections; j++) {
			DWORD start_raw_i = _Pe->pSecHdr[i].PointerToRawData;
			DWORD stop_raw_i  = start_raw_i + _Pe->pSecHdr[i].SizeOfRawData - 1;
			DWORD start_virt_i = _Pe->pSecHdr[i].VirtualAddress;
			DWORD stop_virt_i = start_virt_i + _Pe->pSecHdr[i].Misc.VirtualSize - 1;

			DWORD start_raw_j = _Pe->pSecHdr[j].PointerToRawData;
			DWORD stop_raw_j = start_raw_j + _Pe->pSecHdr[j].SizeOfRawData - 1;
			DWORD start_virt_j = _Pe->pSecHdr[j].VirtualAddress;
			DWORD stop_virt_j = start_virt_j + _Pe->pSecHdr[j].Misc.VirtualSize - 1;

			if (start_raw_i <= stop_raw_j && stop_raw_i >= start_raw_j) {
				printf("Collision raw detected\n");
				exit(1);
			}
			if (start_virt_i <= stop_virt_j && stop_virt_i >= start_virt_j) {
				printf("Collision virt detected between %s and %s\n", _Pe->pSecHdr[i].Name, _Pe->pSecHdr[j].Name);

				exit(1);
			}

			
		}
	}
}


int main(int argc, char* argv[])
{
	// We load both file
	InPeConfig src_pe;
	size_t src_size;
	PVOID src = get_file("C:\\Users\\seb\\source\\repos\\Project1\\x64\\Release\\whoami_origin.exe", &src_size);
	_InitPeStruct(&src_pe, src);
	check_collision(&src_pe);

	InPeConfig dst_pe;
	size_t dst_size;
	//PVOID dst = get_file("C:\\Users\\seb\\source\\repos\\Project1\\x64\\Release\\Project1.exe", &dst_size);
	PVOID dst = get_file("C:\\Users\\seb\\source\\repos\\Project1\\x64\\Release\\whoami_origin.exe", &dst_size);
	_InitPeStruct(&dst_pe, dst);
	check_collision(&dst_pe);


	// compute new image size
	DWORD new_Image_size = dst_pe.pNtHdr->OptionalHeader.SizeOfImage + src_pe.resource_section_hdr->Misc.VirtualSize;//SizeOfRawData

	// compute new_file_size
	size_t new_file_size = dst_size + src_pe.resource_section_hdr->SizeOfRawData;

	// Get new section offset
	DWORD new_section_offset = dst_size;

	// Get new section RVA
	DWORD new_section_RVA = dst_pe.pNtHdr->OptionalHeader.SizeOfImage;

	//DWORD new_section_max_offset_RVA = new_section_offset > new_section_RVA ? new_section_offset : new_section_RVA;

	// allocate
	printf("Allocate\n");
	PVOID new_dst = (PVOID)VirtualAlloc(NULL, new_file_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	// copy original destination
	printf("Copy original destination\n");
	memcpy(new_dst, dst, dst_size);
	InPeConfig new_dst_pe;
	_InitPeStruct(&new_dst_pe, new_dst);

	// clear section
	//printf("Clearing section\n");
	//memset( (PVOID) ((ULONG_PTR)new_dst_pe.base + new_dst_pe.resource_section_hdr->PointerToRawData), 0, new_dst_pe.resource_section_hdr->SizeOfRawData);
	


	// update image size
	printf("updating image size\n");
	new_dst_pe.pNtHdr->OptionalHeader.SizeOfImage = new_Image_size;

	// update section header
	printf("updating section header\n");
	new_dst_pe.resource_section_hdr->Characteristics = src_pe.resource_section_hdr->Characteristics;
	new_dst_pe.resource_section_hdr->Misc.VirtualSize = src_pe.resource_section_hdr->Misc.VirtualSize;
	memcpy(new_dst_pe.resource_section_hdr->Name, src_pe.resource_section_hdr->Name, IMAGE_SIZEOF_SHORT_NAME);
	new_dst_pe.resource_section_hdr->NumberOfLinenumbers = src_pe.resource_section_hdr->NumberOfLinenumbers;
	new_dst_pe.resource_section_hdr->NumberOfRelocations = src_pe.resource_section_hdr->NumberOfRelocations;
	new_dst_pe.resource_section_hdr->PointerToLinenumbers = src_pe.resource_section_hdr->PointerToLinenumbers;
	new_dst_pe.resource_section_hdr->PointerToRelocations = src_pe.resource_section_hdr->PointerToRelocations;
	new_dst_pe.resource_section_hdr->SizeOfRawData = src_pe.resource_section_hdr->SizeOfRawData;
		
	new_dst_pe.resource_section_hdr->PointerToRawData = new_section_offset;
	new_dst_pe.resource_section_hdr->VirtualAddress = new_section_RVA;
	
	
	// update directory
	printf("Update directory\n");
	new_dst_pe.resource_directory->VirtualAddress = new_section_RVA; //
	new_dst_pe.resource_directory->Size = src_pe.resource_directory->Size;

	check_collision(&new_dst_pe);


	// copy new section
	printf("Copying new section");
	PVOID rsrcSection_src = (PVOID)((ULONG_PTR)src_pe.base + (ULONG_PTR)src_pe.resource_section_hdr->PointerToRawData);
	PVOID rsrcSection_new_dst = (PVOID)((ULONG_PTR)new_dst_pe.base + new_section_offset);//new_section_offset
	DWORD size = src_pe.resource_section_hdr->SizeOfRawData;
	memcpy(rsrcSection_new_dst, rsrcSection_src, size);

	// write file
	printf("Write file\n");
	FILE* file = NULL;
	fopen_s(&file, "C:\\Users\\seb\\source\\repos\\Project1\\x64\\Release\\output.exe", "wb");
	fwrite(new_dst, 1, new_file_size, file);
	fclose(file);


	// Est ce que les info du directory sont les meme que dans le header de section en ce qui concerne la RVA et la taille?


}