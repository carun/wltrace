#include <windows.h>
#include <stdio.h>

void
WinPerror(char *message)
{
	DWORD err = GetLastError();
	static char emsg[FORMAT_MESSAGE_MAX_WIDTH_MASK];

	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
					  NULL, err, 0, emsg, sizeof(emsg), NULL))
	{
		fprintf(stderr, "%s:%s (%u)\n",message, emsg, err);
	}
	else
	{
		fprintf(stderr, "%s: Unknown error %u\n", message, err);
	}
}

BOOL 
FindSection(HANDLE f, DWORD StartOfSections, DWORD NumSections, PIMAGE_SECTION_HEADER Section, DWORD Addr)
{
	DWORD len;
	unsigned int i;

	SetFilePointer(f, StartOfSections, NULL, FILE_BEGIN);

	for(i=0;i<NumSections;i++)
	{
		if (!ReadFile(f, (LPVOID)Section, sizeof(IMAGE_SECTION_HEADER), &len, NULL))
		{
			WinPerror("ReadFile(section_hdr)");
			return FALSE;
		}

		if (Section->VirtualAddress <= Addr &&
				(Section->VirtualAddress + Section->Misc.VirtualSize) > Addr)
		{
			return TRUE;
		}
	}

	return FALSE;
}

void
ShowDeps(char *filename)
{
	HANDLE *f;
	IMAGE_DOS_HEADER dos_hdr;
	IMAGE_NT_HEADERS32 nthdrs;
	IMAGE_SECTION_HEADER Section;
	DWORD len;

	f = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0,
					NULL);

	if (f == INVALID_HANDLE_VALUE) 
	{
		WinPerror(filename);
		goto quit;
	}

	if ((!ReadFile(f, (LPVOID)&dos_hdr, sizeof(IMAGE_DOS_HEADER), &len, NULL)) || (len != sizeof(IMAGE_DOS_HEADER)))
	{
		fprintf(stderr, "Truncated MSDOS header\n");
		goto quit;
	}

	if (SetFilePointer(f, dos_hdr.e_lfanew, NULL, FILE_BEGIN) == (DWORD)-1) 
	{
		WinPerror("SetFilePointer(e_lfanew)");
		goto quit;
	}

	if ((!ReadFile(f, (LPVOID)&nthdrs, sizeof(IMAGE_NT_HEADERS32), &len, NULL)) || (len != sizeof(IMAGE_NT_HEADERS32)))
	{
		fprintf(stderr, "Truncated PECOFF file\n");
		goto quit;
	}

	if (nthdrs.Signature != 0x00004550)	/* 'PE\0\0' */
	{
		fprintf(stderr, "Bad PE signature\n");
		goto quit;
	}

	if (nthdrs.FileHeader.Machine != IMAGE_FILE_MACHINE_I386) 
	{
		fprintf(stderr, "%u %x\n",nthdrs.FileHeader.Machine,nthdrs.FileHeader.Machine);
		fprintf(stderr, "Unsupported architecture\n");
		goto quit;
	}

	if (nthdrs.FileHeader.SizeOfOptionalHeader == 0) 
	{
		fprintf(stderr, "Not an executable image\n");
		goto quit;
	}

	if (nthdrs.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		fprintf(stderr, "Bad Magic number in COFF optional header\n");
		goto quit;
	}

	if ((nthdrs.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) &&
		(nthdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0))
	{
		PIMAGE_DATA_DIRECTORY import;
		DWORD itable, SectionMarker;
		char DLLname[1024];

		import = &nthdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		SectionMarker = SetFilePointer(f, 0, NULL, FILE_CURRENT);

		if (!FindSection(f, SectionMarker, nthdrs.FileHeader.NumberOfSections, &Section, nthdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress))
		{
			fprintf(stderr, "Can't locate import table\n");
			goto quit;
		}

		itable = (DWORD)Section.PointerToRawData + (import->VirtualAddress - Section.VirtualAddress);

		while(1)
		{
			IMAGE_IMPORT_DESCRIPTOR idesc;

			SetFilePointer(f, (LONG)itable, NULL, FILE_BEGIN);

			if (!ReadFile(f, &idesc, sizeof(idesc), &len, NULL))
			{
				WinPerror("ReadFile(lib->itable[n])");
				break;
			}

			(char*)itable += sizeof(idesc);

			if (idesc.Characteristics == 0)
			{
				/* End of Import Directory Table */
				break;
			}

			if (!FindSection(f, SectionMarker, nthdrs.FileHeader.NumberOfSections, &Section, idesc.Name))
			{
				fprintf(stderr, "Can't locate imported library name\n");
				goto quit;
			}

			SetFilePointer(f, (Section.PointerToRawData + (idesc.Name - Section.VirtualAddress)), NULL, FILE_BEGIN);
			
			if (!ReadFile(f, DLLname, sizeof(DLLname), &len, NULL))
			{
				WinPerror("ReadFile(lib->itable[n].name)");
				break;
			}

			printf("%s\n", DLLname);
		}
	}

quit:
	CloseHandle(f);
}

/* $Id: deps.c,v 1.1 2002/11/25 04:55:25 john Exp $ -- EOF */
