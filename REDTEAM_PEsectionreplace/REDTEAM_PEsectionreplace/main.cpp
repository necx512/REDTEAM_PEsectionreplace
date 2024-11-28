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

void switch_section(PIMAGE_SECTION_HEADER sectionA, PIMAGE_SECTION_HEADER sectionB)
{
	IMAGE_SECTION_HEADER tmp = *sectionA;
	*sectionA = *sectionB;
	*sectionB = tmp;
}
void sort_section_table(PInPeConfig _Pe)
{
	WORD nbSections = _Pe->pNtHdr->FileHeader.NumberOfSections;
	bool changed = FALSE;

	
	do
	{
		changed = FALSE;
		for (int i = 0; i < _Pe->pNtHdr->FileHeader.NumberOfSections - 1; i++) {
			for (int j = i + 1; j < _Pe->pNtHdr->FileHeader.NumberOfSections; j++) {
				if (_Pe->pSecHdr[i].VirtualAddress > _Pe->pSecHdr[j].VirtualAddress) {// or _Pe->pSecHdr[i].PointerToRawData??

					changed = TRUE;
					printf("switch : %lx %lx / %s %s\n", _Pe->pSecHdr[i].Misc.VirtualSize, _Pe->pSecHdr[j].Misc.VirtualSize, _Pe->pSecHdr[i].Name, _Pe->pSecHdr[j].Name);
					switch_section(&_Pe->pSecHdr[i], &_Pe->pSecHdr[j]);
					
				}
			}
		}
	} while (changed == TRUE);
}


// Pour chaque IMAGE_RESOURCE_DIRECTORY il y a plusieurs IMAGE_RESOURCE_DIRECTORY_ENTRY dont la premiere commence juste apres l'IMAGE_RESOURCE_DIRECTORY
// IMAGE_RESOURCE_DIRECTORY_ENTRY peut etre nommée ou non
void read_ressources_dir(PInPeConfig _Pe, PIMAGE_RESOURCE_DIRECTORY dir,int level, DWORD diff)
{
	PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(dir + 1);
	printf("%*sdir->NumberOfNamedEntries = %ld. ", 4 * level, "", dir->NumberOfNamedEntries);
	printf("%*sdir->NumberOfIdEntrie = %ld. ", 4 * level, "",dir->NumberOfIdEntries);
	printf("%*sRES DIR = %p\n", 4 * level,"",dir);
	for (int i = 0; i < dir->NumberOfNamedEntries + dir->NumberOfIdEntries; i++) {		
		/*printf("%*d----------DataIsDirectory:%lx\n", 4 * level, i, entries[i].DataIsDirectory);
		printf("%*d----------Id:%lx\n", 4 * level,i, entries[i].Id);
		printf("%*d----------Name:%lx\n", 4 * level,i, entries[i].Name);
		printf("%*d----------NameIsString:%lx\n", 4 * level,i, entries[i].NameIsString);
		printf("%*d----------NameOffset:%lx\n", 4 * level,i, entries[i].NameOffset);
		printf("%*d----------OffsetToData:%lx\n", 4 * level,i, entries[i].OffsetToData);
		printf("%*d----------OffsetToDirectory:%lx\n", 4 * level, i, entries[i].OffsetToDirectory);*/

		/*if (entries[i].NameIsString) {
			PIMAGE_RESOURCE_DIR_STRING_U str = (PIMAGE_RESOURCE_DIR_STRING_U)((PCHAR)dir + entries[i].NameOffset);
			str->Length;
			char* ret = (char*)malloc(str->Length + 1);
			memset(ret, 0, str->Length + 1);
			WideCharToMultiByte(CP_ACP, NULL, (LPCWCH)&str->NameString, str->Length, ret, str->Length, NULL, NULL);
			printf("Name : %s\n", ret);


		}*/

		if (entries[i].DataIsDirectory) {
			PIMAGE_RESOURCE_DIRECTORY sub_dir = (PIMAGE_RESOURCE_DIRECTORY)((PCHAR)_Pe->base + _Pe->resource_section_hdr->VirtualAddress + entries[i].OffsetToDirectory);
			read_ressources_dir(_Pe, sub_dir,level+1,diff);
		}
		else
		{
			PIMAGE_RESOURCE_DATA_ENTRY data_entry = (PIMAGE_RESOURCE_DATA_ENTRY)((PCHAR)_Pe->base + _Pe->resource_section_hdr->VirtualAddress + entries[i].OffsetToData);
			
			printf("%lx -> ", data_entry->OffsetToData);
			data_entry->OffsetToData += diff;
			printf("%lx\n", data_entry->OffsetToData);
		}
	}
}

void read_ressources(PInPeConfig _Pe, DWORD diff) {
	read_ressources_dir(_Pe,(PIMAGE_RESOURCE_DIRECTORY) ((PCHAR)_Pe->base + _Pe->resource_section_hdr->PointerToRawData),0, diff);

}



void same_virtualsize_as_rawisze(PInPeConfig _Pe)
{
	for (int i = 0; i < _Pe->pNtHdr->FileHeader.NumberOfSections ; i++) {
		if (_Pe->pSecHdr[i].Misc.VirtualSize < _Pe->pSecHdr[i].SizeOfRawData) {
			_Pe->pSecHdr[i].Misc.VirtualSize = _Pe->pSecHdr[i].SizeOfRawData;
		}
		else {
			_Pe->pSecHdr[i].SizeOfRawData = _Pe->pSecHdr[i].Misc.VirtualSize;
		}
	}
}



DWORD getSpaceBetweenDOSHeaderAndNTHeader(PInPeConfig _Pe) {
	return _Pe->pDosHdr->e_lfanew - sizeof(IMAGE_DOS_HEADER);
}

DWORD getSpaceBetweenHeadersAndFirstSection(PInPeConfig _Pe) {
	if (sizeof(IMAGE_SECTION_HEADER) != 40) {
		printf("FATAL\n");
		exit(1);
	}
	DWORD endSectionsHdrOffset = _Pe->pDosHdr->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * (_Pe->pNtHdr->FileHeader.NumberOfSections);
	return _Pe->pNtHdr->OptionalHeader.SizeOfHeaders - endSectionsHdrOffset;
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

	if (getSpaceBetweenHeadersAndFirstSection(_Pe) < sizeof(IMAGE_SECTION_HEADER)) {
		fprintf(stderr, "FATAL Not enough space to create section\n");
		exit(1);
	}


	DWORD offsetToNewSectionHdr = _Pe->pDosHdr->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * (_Pe->pNtHdr->FileHeader.NumberOfSections);
	
	// Get Last section header
	IMAGE_SECTION_HEADER lastSectionHdr = _Pe->pSecHdr[_Pe->pNtHdr->FileHeader.NumberOfSections - 1];

	// New Section
	PIMAGE_SECTION_HEADER newSectionHdr = &_Pe->pSecHdr[_Pe->pNtHdr->FileHeader.NumberOfSections];

	// Duplicate
	*newSectionHdr = lastSectionHdr;

	// update addresses
	newSectionHdr->VirtualAddress = lastSectionHdr.VirtualAddress + lastSectionHdr.Misc.VirtualSize;
	if (newSectionHdr->VirtualAddress % aligment != 0)
		newSectionHdr->VirtualAddress = (newSectionHdr->VirtualAddress / aligment) * aligment + aligment;
	
	newSectionHdr->PointerToRawData = lastSectionHdr.PointerToRawData + lastSectionHdr.SizeOfRawData;
	if (newSectionHdr->PointerToRawData % aligment != 0)
		newSectionHdr->VirtualAddress = (newSectionHdr->PointerToRawData / aligment) * aligment + aligment;

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
	check_collision(&src_pe);

	InPeConfig dst_pe;
	size_t dst_size;
	//PVOID dst = get_file("C:\\Users\\seb\\source\\repos\\Project1\\x64\\Release\\Project1.exe", &dst_size);
	PVOID dst = get_file("C:\\Users\\seb\\source\\repos\\Project1\\x64\\Release\\whoami_origin.exe", &dst_size);
	_InitPeStruct(&dst_pe, dst);
	check_collision(&dst_pe);
	DWORD RVA_originrsrcSection = dst_pe.resource_section_hdr->VirtualAddress;
	

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


	DWORD diff = dst_pe.resource_section_hdr->VirtualAddress - RVA_originrsrcSection;
	printf("DIFF = %lx\n", diff);

	read_ressources(&dst_pe, diff); //UPDATE

	// Clear original section
	PCHAR ptr = (PCHAR)dst_pe.base + original_rsrc_section_hdr->PointerToRawData;
	memset(ptr, 0, original_rsrc_section_hdr->SizeOfRawData);

	// clear name
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