#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include <psapi.h>
#include <time.h>


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
	_Pe->resource_section_hdr = &_Pe->pSecHdr[get_sectionoffset_from_RVA(_Pe,_Pe->resource_directory->VirtualAddress)];
}

// Pour chaque IMAGE_RESOURCE_DIRECTORY il y a plusieurs IMAGE_RESOURCE_DIRECTORY_ENTRY dont la premiere commence juste apres l'IMAGE_RESOURCE_DIRECTORY
// IMAGE_RESOURCE_DIRECTORY_ENTRY peut etre nommée ou non
void read_ressources_dir(PInPeConfig _Pe, PIMAGE_RESOURCE_DIRECTORY dir,int level, DWORD RVA_originrsrcSection, DWORD RVA_newsrcSection)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(dir + 1);
	for (int i = 0; i < dir->NumberOfNamedEntries + dir->NumberOfIdEntries; i++) {		
		if (entries[i].DataIsDirectory) {
			PIMAGE_RESOURCE_DIRECTORY sub_dir = (PIMAGE_RESOURCE_DIRECTORY)((PCHAR)_Pe->base + _Pe->resource_section_hdr->PointerToRawData + entries[i].OffsetToDirectory);
			read_ressources_dir(_Pe, sub_dir,level+1, RVA_originrsrcSection, RVA_newsrcSection);
		}
		else
		{
			PIMAGE_RESOURCE_DATA_ENTRY data_entry = (PIMAGE_RESOURCE_DATA_ENTRY)((PCHAR)_Pe->base + _Pe->resource_section_hdr->PointerToRawData + entries[i].OffsetToData);
			data_entry->OffsetToData = data_entry->OffsetToData - RVA_originrsrcSection + RVA_newsrcSection;
		}
	}
}

void read_ressources(PInPeConfig _Pe,DWORD RVA_originrsrcSection, DWORD RVA_newsrcSection) {
	printf("[read_ressources] _Pe->resource_section_hdr->PointerToRawData = %lx\n", _Pe->resource_section_hdr->PointerToRawData);
	printf("[read_ressources] diff = %lx\n", RVA_newsrcSection- RVA_originrsrcSection);

	read_ressources_dir(_Pe,(PIMAGE_RESOURCE_DIRECTORY) ((PCHAR)_Pe->base + _Pe->resource_section_hdr->PointerToRawData),0, RVA_originrsrcSection, RVA_newsrcSection);

}


DWORD getSpaceBetweenHeadersAndFirstSection(PInPeConfig _Pe) {
	if (sizeof(IMAGE_SECTION_HEADER) != 40) {
		printf("FATAL\n");
		exit(1);
	}
	DWORD endSectionsHdrOffset = _Pe->pDosHdr->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * (_Pe->pNtHdr->FileHeader.NumberOfSections);
	return _Pe->pNtHdr->OptionalHeader.SizeOfHeaders - endSectionsHdrOffset;
}

void print_section_name(IMAGE_SECTION_HEADER hdr) {
	for (int i = 0; i < IMAGE_SIZEOF_SHORT_NAME && hdr.Name[i] != 0;++i) {
		printf("%c", hdr.Name[i]);
	}
	printf("\n");
	
}
PCHAR create_new_header(PInPeConfig _Pe, DWORD fileSize, DWORD size/*section size*/) {

	DWORD aligment = _Pe->pNtHdr->OptionalHeader.SectionAlignment;

	/*if (size % _Pe->pNtHdr->OptionalHeader.SectionAlignment != 0) {
		fprintf(stderr, "FATAL : The size of the section you want to create is not align with SectionAlignment\n");
		exit(2);
	}
	if (size % _Pe->pNtHdr->OptionalHeader.FileAlignment != 0) {
		fprintf(stderr, "FATAL : The size of the section you want to create is not align with FileAlignment\n");
		exit(2);
	}*/

	DWORD emptySpace = getSpaceBetweenHeadersAndFirstSection(_Pe);
	printf("getSpaceBetweenHeadersAndFirstSection(_Pe) = %ld\n", emptySpace);
	if (emptySpace < sizeof(IMAGE_SECTION_HEADER)) {
		fprintf(stderr, "FATAL Not enough space to create section\n");
		exit(1);
	}


	DWORD offsetToNewSectionHdr = _Pe->pDosHdr->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * (_Pe->pNtHdr->FileHeader.NumberOfSections);
	
	printf("NbSections = %d\n", _Pe->pNtHdr->FileHeader.NumberOfSections);
	
	// Get Last section header
	IMAGE_SECTION_HEADER lastSectionHdr = _Pe->pSecHdr[_Pe->pNtHdr->FileHeader.NumberOfSections - 1];
	print_section_name(lastSectionHdr);


	// New Section
	PIMAGE_SECTION_HEADER newSectionHdr = &_Pe->pSecHdr[_Pe->pNtHdr->FileHeader.NumberOfSections];

	// Duplicate
	*newSectionHdr = lastSectionHdr;

	// update addresses
	printf("lastSectionHdr.VirtualAddress = %lx\n", lastSectionHdr.VirtualAddress);
	newSectionHdr->VirtualAddress = lastSectionHdr.VirtualAddress + lastSectionHdr.Misc.VirtualSize;
	
	if (newSectionHdr->VirtualAddress % aligment != 0)
		newSectionHdr->VirtualAddress = (newSectionHdr->VirtualAddress / aligment) * aligment + aligment;
	printf("newSectionHdr->VirtualAddress = %lx\n", newSectionHdr->VirtualAddress);
	
	newSectionHdr->PointerToRawData = lastSectionHdr.PointerToRawData + lastSectionHdr.SizeOfRawData;
	if (newSectionHdr->PointerToRawData != fileSize) {
		fprintf(stderr, "FATAL, newSectionHdr->PointerToRawData != fileSize\n");
		fprintf(stderr, "This is a issue because we assume that the new section will be directly mapped to the end of the file\n");
		exit(2);
	}
	/*if (newSectionHdr->PointerToRawData % aligment != 0)
		newSectionHdr->PointerToRawData = (newSectionHdr->PointerToRawData / aligment) * aligment + aligment;*/

	// update size
	

	
	newSectionHdr->Misc.VirtualSize = size;
	newSectionHdr->SizeOfRawData = size;

	

	// change Name
	newSectionHdr->Name[0] = '.';
	newSectionHdr->Name[1] = 'r';
	newSectionHdr->Name[2] = 's';
	newSectionHdr->Name[3] = 'r';
	newSectionHdr->Name[4] = 'c';
	newSectionHdr->Name[5] = '\0';


	// Increment the number of sections
	_Pe->pNtHdr->FileHeader.NumberOfSections = _Pe->pNtHdr->FileHeader.NumberOfSections + 1;

	//update ImageSize
	_Pe->pNtHdr->OptionalHeader.SizeOfImage = _Pe->pNtHdr->OptionalHeader.SizeOfImage + size;
	
	// reallocate new file and init the new section to zero
	PCHAR new_space = (PCHAR)VirtualAlloc(NULL, fileSize + size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	new_space[fileSize] = 0xff;
	memcpy(new_space,_Pe->base, fileSize);
	free(_Pe->base);
	_InitPeStruct(_Pe, new_space);

	return &new_space[fileSize];


}



int main(int argc, char* argv[])
{
	// We load both file
	InPeConfig src_pe;
	size_t src_size;
	PVOID src = get_file("C:\\Users\\seb\\source\\repos\\Project1\\x64\\Release\\whoami_origin.exe", &src_size);
	_InitPeStruct(&src_pe, src);
	DWORD RVA_originrsrcSection = src_pe.resource_section_hdr->VirtualAddress;
	

	InPeConfig dst_pe;
	size_t dst_size;
	PVOID dst = get_file("C:\\Users\\seb\\source\\repos\\Project1\\x64\\Release\\Project1.exe", &dst_size);
	//PVOID dst = get_file("C:\\Users\\seb\\source\\repos\\Project1\\x64\\Release\\whoami_origin.exe", &dst_size);
	_InitPeStruct(&dst_pe, dst);
	
	

	DWORD new_file_size = dst_size + src_pe.resource_section_hdr->SizeOfRawData;
	PCHAR new_section = create_new_header(&dst_pe, dst_size,src_pe.resource_section_hdr->SizeOfRawData);
	


	// copy new section
	printf("Copying new section");
	PVOID rsrcSection_src = (PVOID)((ULONG_PTR)src_pe.base + (ULONG_PTR)src_pe.resource_section_hdr->PointerToRawData);
	DWORD size = src_pe.resource_section_hdr->SizeOfRawData;
	memcpy(new_section, rsrcSection_src, size);


	// update directory
	printf("Update directory\n");
	PIMAGE_SECTION_HEADER original_rsrc_section_hdr = dst_pe.resource_section_hdr;// dst_pe.resource_section_hdr will be computed from dst_pe.resource_directory so we need to save it
	dst_pe.resource_directory->VirtualAddress = dst_pe.pSecHdr[dst_pe.pNtHdr->FileHeader.NumberOfSections - 1].VirtualAddress; //UPDATE
	dst_pe.resource_directory->Size = dst_pe.pSecHdr[dst_pe.pNtHdr->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
	_InitPeStruct(&dst_pe, dst_pe.base);


	
	DWORD RVA_newsrcSection = dst_pe.resource_section_hdr->VirtualAddress;
	printf("..........dst_pe.resource_section_hdr->VirtualAddress = %lx\n", RVA_newsrcSection);
	//printf("DIFF = %lx\n", diff);

	read_ressources(&dst_pe, RVA_originrsrcSection, RVA_newsrcSection); //UPDATE

	// Clear original section
	printf("Clear original section\n");
	PCHAR ptr = (PCHAR)dst_pe.base + original_rsrc_section_hdr->PointerToRawData;
	memset(ptr, 0, original_rsrc_section_hdr->SizeOfRawData);

	// clear name
	printf("Clear name\n");
	original_rsrc_section_hdr->Name[0] = 'o'; // '.'


	//TODO checksum

	



	// write file
	printf("Write file\n");
	FILE* file = NULL;
	fopen_s(&file, "C:\\Users\\seb\\source\\repos\\Project1\\x64\\Release\\output.exe", "wb");
	fwrite(dst_pe.base, 1, new_file_size, file);
	fclose(file);




	return 0;
}