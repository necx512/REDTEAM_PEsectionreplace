#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include <psapi.h>
typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

struct pe_structs
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeader;
	PIMAGE_SECTION_HEADER secHeader;
	PIMAGE_DATA_DIRECTORY dataDirectory;
};


typedef struct _InPeConfig {
	PVOID base;
	PIMAGE_DOS_HEADER		pDosHdr;
	PIMAGE_NT_HEADERS		pNtHdr;
	PIMAGE_SECTION_HEADER	pSecHdr;
} InPeConfig, * PInPeConfig;

unsigned char* get_file(const char* filename, size_t* ret_size) {

	FILE* file = fopen(filename, "rb");
	if (file == NULL) {
		return NULL;
	}
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);
	unsigned char* pe_mem = calloc(1, size);
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

void _InitPeStruct(PInPeConfig _Pe, PVOID pPeAddress, SIZE_T sPeSize) {
	_Pe->base = pPeAddress;
	_Pe->pDosHdr = (PIMAGE_DOS_HEADER)pPeAddress;
	_Pe->pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pPeAddress + _Pe->pDosHdr->e_lfanew);
	_Pe->pSecHdr = (PIMAGE_SECTION_HEADER)((SIZE_T)_Pe->pNtHdr + sizeof(IMAGE_NT_HEADERS));
}


PIMAGE_SECTION_HEADER find_section_by_name(const char* sectionName, InPeConfig pe)
{
	for (int i = 0; i < pe.pNtHdr->FileHeader.NumberOfSections; i++) {
		if (strncmp((const char*)pe.pSecHdr[i].Name, sectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
			return &pe.pSecHdr[i];
		}
	}
}

PVOID get_section_addr(PIMAGE_SECTION_HEADER section, InPeConfig pe) {
	return (PVOID)((ULONG_PTR)pe.base + section->PointerToRawData);
}

size_t get_section_size(PIMAGE_SECTION_HEADER section) {
	return section->SizeOfRawData;
}

void clear_section(PIMAGE_SECTION_HEADER section, InPeConfig pe) {
	PVOID addr = get_section_addr(section, pe);
	size_t size = get_section_size(section);
	memset(addr, 0, size);
	section->PointerToRawData = 0;
	section->SizeOfRawData = 0;
}



void set_section(PIMAGE_SECTION_HEADER section_src, InPeConfig pe_src, PIMAGE_SECTION_HEADER dst_section, InPeConfig pe_dst, PVOID new_addr) {
	PVOID addr = get_section_addr(section_src, pe_src);
	size_t size = get_section_size(section_src);

	dst_section->PointerToRawData = (ULONG_PTR)new_addr - (ULONG_PTR)pe_dst.base;
	dst_section->SizeOfRawData = size;

	memcpy(new_addr, addr, size);

}



int main(int argc, char *argv[])
{
	// We load both file
	InPeConfig src_pe;
	size_t src_size;
	unsigned char* src = get_file(argv[1], &src_size);
	_InitPeStruct(&src_pe, src, src_size);

	InPeConfig dst_pe;
	size_t dst_size;
	unsigned char* dst = get_file(argv[2], &dst_size);
	_InitPeStruct(&dst_pe, dst, dst_size);


	// get the source section
	PIMAGE_SECTION_HEADER src_section = find_section_by_name(".rsrc", src_pe);

	// duplicate dst_pe with more space for
	size_t new_img_size = dst_size + get_section_size(src_section);
	PVOID new_dst = (PVOID)VirtualAlloc(NULL, new_img_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	memcpy(new_dst, dst, new_img_size);


	// clear the destination section
	PIMAGE_SECTION_HEADER dst_section = find_section_by_name(".rsrc", dst_pe);
	clear_section(dst_section, dst_pe);









	// remove the section in dst if it exists
	unsigned char* ptr_workedSection_dst = NULL;
	size_t size_workedSection_dst = 0;
	bool workedSection_found = false;

	

	int i;
	for (i = 0; i < dst_pe.pNtHdr->FileHeader.NumberOfSections; i++) {
		if (strncmp((const char*)dst_pe.pSecHdr[i].Name, workedSectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
			if (dst_pe.pSecHdr[i].PointerToRawData != 0) {
				ptr_workedSection_dst = (unsigned char*)((ULONG_PTR)src + dst_pe.pSecHdr[i].PointerToRawData);
				size_workedSection_dst = dst_pe.pSecHdr[i].SizeOfRawData;
				memset(ptr_workedSection_dst, 0, size_workedSection_dst);
			}
			break;
		}
	}
	if (i == dst_pe.pNtHdr->FileHeader.NumberOfSections) {
		fprintf(stderr, "FATAL The section %s was not found in dst\n", workedSectionName);
		return -1;
	}


	// TODO check if dst_pe.pNtHdr->OptionalHeader.SizeOfImage == dst_size
	// We will copy the section at the end of file 
	size_t new_img_size = dst_size + size_workedSection_src;
	unsigned char *new_dst = (unsigned char*)VirtualAlloc(NULL, dst_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	unsigned char* ptr_workedSection_newdst = new_dst + dst_size;
	memcpy(new_dst, dst, new_img_size);	
	memcpy(ptr_workedSection_newdst, ptr_workedSection_src, size_workedSection_src);


	
	//dst_pe.pNtHdr->OptionalHeader.SizeOfImage have to be changed
	InPeConfig newdst_pe;
	_InitPeStruct(&newdst_pe, new_dst, new_img_size);

	//update SizeOfImage
	newdst_pe.pNtHdr->OptionalHeader.SizeOfImage = new_img_size;//y'a pas une histoire d'endness là big endian?

	//We do not need to update the number of section. We assume that the section exist before
	//update section header
	for (int i = 0; i < newdst_pe.pNtHdr->FileHeader.NumberOfSections; i++) {
		if (strncmp((const char*)newdst_pe.pSecHdr[i].Name, workedSectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
			ptr_workedSection_dst = (unsigned char*)((ULONG_PTR)src + newdst_pe.pSecHdr[i].PointerToRawData);
			newdst_pe.pSecHdr[i].PointerToRawData = (ULONG_PTR)ptr_workedSection_newdst - (ULONG_PTR)new_dst;
			newdst_pe.pSecHdr[i].SizeOfRawData = size_workedSection_src;
		}
	}
	return 0;
}