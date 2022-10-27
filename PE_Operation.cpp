// PE.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <stdio.h>
#include <malloc.h>
#include "function.h"
FILE* file_open()
{
	FILE* fp=fopen("C:\\Users\\HP\\Desktop\\1.exe","rb+");
	return fp;
}
FILE* file_write()
{
	FILE* fn=fopen("C:\\Users\\HP\\Desktop\\123.exe","wb");
	return fn;
}
//******************************************************find the "PE"
uint find_PE()
{
	FILE* fp;
	fp=file_open();
	if (fp!=NULL)
	{
		uchar a,b;
		uint pe;
		a=fgetc(fp);
		b=fgetc(fp);
		if ((a=='M') && (b=='Z'))
		{
			fseek(fp,60L,0);
			pe=fgetc(fp);
			fseek(fp,pe,0);
			a=fgetc(fp);
			b=fgetc(fp);
			if ((a=='P') && (b=='E'))
			{
				fclose(fp);
				return pe;
			}
		}else
		{
			printf("Not a .exe");
			return 0;
		}
	}else return 0;
}
//*****************************************************save standard PE head
uchar* store_PE(uint pe)
{
	uchar* ch;
	FILE* fp;
	fp=file_open();
	if (fp!=NULL)
	{
		ch=(uchar*)malloc(28);
		if (ch!=NULL)
		{
			fseek(fp,pe+4,0);
			for (int i=0;i<20;i++)
			{
				*ch=fgetc(fp);
				ch++;
			}
			fclose(fp);
			return ch-i;
		}else 
		{
			printf("Not enough space");
			fclose(fp);
			return NULL;
		}
	}else return NULL;
}
//*****************************************************print section table
uint pri_Section(uint pe)
{
	FILE* fp;
	fp=file_open();
	ushort NumberOfSections,SizeOfOptionalHeader;
	if(fp!=NULL)
	{
		fseek(fp,pe+6,0);
		fread(&NumberOfSections,2,1,fp);
		fseek(fp,pe+20,0);
		fread(&SizeOfOptionalHeader,2,1,fp);
		fseek(fp,pe+24+SizeOfOptionalHeader,0);
		for (int j=0;j<NumberOfSections;j++)
		{
			for (int i=0;i<40;i++)
			{
				printf("%02x ",fgetc(fp));
			}
			printf("\n");
		}
		fclose(fp);
	}else return 0;
}
//****************************************************
//****************************************************FileBuffer get VirtualSize
uint vs(uint pe,char num)
{
	FILE* fp;
	ushort SizeOfOptionalHeader;
	uint VirtualSize;
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+20,0);
		fread(&SizeOfOptionalHeader,2,1,fp);
		fseek(fp,pe+24+SizeOfOptionalHeader+8+num*40,0);
		fread(&VirtualSize,4,1,fp);
	}else return 0;
	fclose(fp);
	return VirtualSize;
}
//****************************************************FileBuffer get PointerToRawData
uint ptrd(uint pe,char num)
{
	FILE* fp;
	ushort SizeOfOptionalHeader;
	uint PointerToRawData;
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+20,0);
		fread(&SizeOfOptionalHeader,2,1,fp);
		fseek(fp,pe+24+SizeOfOptionalHeader+20+num*40,0);
		fread(&PointerToRawData,4,1,fp);
	}else return 0;
	fclose(fp);
	return PointerToRawData;
}
//***************************************************FileBuffer get VirtualAddress
uint va(uint pe,char num)
{
	FILE* fp;
	ushort SizeOfOptionalHeader;
	uint VirtualAddress;
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+20,0);
		fread(&SizeOfOptionalHeader,2,1,fp);
		fseek(fp,pe+24+SizeOfOptionalHeader+12+num*40,0);
		fread(&VirtualAddress,4,1,fp);
	}else return 0;
	fclose(fp);
	return VirtualAddress;
}
//****************************************************FileBuffer get SizeOfRawData
uint sord(uint pe,char num)
{
	FILE* fp;
	ushort SizeOfOptionalHeader;
	uint SizeOfRawData;
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+20,0);
		fread(&SizeOfOptionalHeader,2,1,fp);
		fseek(fp,pe+24+SizeOfOptionalHeader+16+num*40,0);
		fread(&SizeOfRawData,4,1,fp);
	}else return 0;
	fclose(fp);
	return SizeOfRawData;
}
//**************************************************copy section(FileBuffer -> ImageBuffer)
uchar Section_Copy(uchar* ch,uint pe,uint size,uint add_file,uint add_image)
{
	FILE* fp;
	ch=ch+add_image;
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,add_file,0);
		for (uint i=0;i<size;i++)
		{
			*ch=fgetc(fp);
			ch++;
		}
	}else return 0;
	fclose(fp);
	return 1;
}
//*******************************************************file out put
uchar file_out(uchar* ch,uint size)
{
	FILE* fo;
	uchar data;
	fo=file_write();
	if (fo!=NULL)
	{
		for (int i=0;i<size;i++)
		{
			data=*ch;
			fputc(data,fo);
			ch++;
		}
		fclose(fo);
		return 1;
	}else
	{
		printf("New file creation failed");
		return 0;
	}
}
//*************************************************size of NewBuffer(operation in ImageBuffer)
uint NewBuffer_size(uchar* ch)
{
	ushort NumberOfSections,SizeOfOptionalHeader;
	uint PE_add,PointerToRawData,SizeOfRawData,SizeOfHeaders,VirtualAddress;
	PE_add=*(uint*)(ch+0x3c);
	NumberOfSections=*(ushort*)(ch+PE_add+6);
	SizeOfOptionalHeader=*(ushort*)(ch+PE_add+20);
	PointerToRawData=*(uint*)(ch+PE_add+24+SizeOfOptionalHeader+20+(NumberOfSections-1)*40);
	SizeOfRawData=*(uint*)(ch+PE_add+24+SizeOfOptionalHeader+16+(NumberOfSections-1)*40);
	return PointerToRawData+SizeOfRawData;
}
//***********************************************get SizeOfImage
uint Image_size()
{
	FILE* fp;
	uint pe,SizeOfImage;
	fp=file_open();
	pe=find_PE();
	if (fp!=NULL)
	{
		fseek(fp,pe+80,0);
		fread(&SizeOfImage,4,1,fp);
	}else return 0;
	fclose(fp);
	return SizeOfImage;
}
//***********************************************get AddressOfEntryPoint
uint EntryPoint_add(uint pe)
{
	FILE* fp;
	uint AddressOfEntryPoint;
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+24+16,0);
		fread(&AddressOfEntryPoint,4,1,fp);
	}else return 0;
	fclose(fp);
	return AddressOfEntryPoint;
}
//***************************************************get SizeOfOptionalHeader
ushort optional_size()
{
	FILE* fp;
	ushort SizeOfOptionalHeader;
	uint pe;
	pe=find_PE();
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+20,0);
		fread(&SizeOfOptionalHeader,2,1,fp);
	}else return 0;
	fclose(fp);
	return SizeOfOptionalHeader;
}
//****************************************************get SizeOfHeaders
uint header_size()
{
	FILE* fp;
	uint pe,SizeOfHeaders;
	pe=find_PE();
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+84,0);
		fread(&SizeOfHeaders,4,1,fp);
	}else return 0;
	fclose(fp);
	return SizeOfHeaders;
}
//***************************************************get NumberOfSections
ushort section_num()
{
	FILE* fp;
	ushort NumberOfSections;
	uint pe;
	pe=find_PE();
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+6,0);
		fread(&NumberOfSections,2,1,fp);
	}else return 0;
	fclose(fp);
	return NumberOfSections;
}
//*****************************************************FileBuffer -> ImageBuffer
uchar* stretching(uint pe)
{
	FILE* fp;
	uchar* ImageBuffer;
	fp=file_open();
	if (fp!=NULL)
	{
		ushort NumberOfSections;
		uint SizeOfHeaders,SizeOfImage;
		SizeOfImage=Image_size();
		NumberOfSections=section_num();
		SizeOfHeaders=header_size();
		ImageBuffer=(uchar*)malloc(SizeOfImage);
		if (ImageBuffer!=NULL)
		{
			for (uint j=0;j<SizeOfImage;j++)
			{
				*ImageBuffer=0;
				ImageBuffer++;
			}
			ImageBuffer=ImageBuffer-SizeOfImage;
			fseek(fp,0,0);
			for (uint i=0;i<SizeOfHeaders;i++)
			{
				fread(ImageBuffer,1,1,fp);
				ImageBuffer++;
			}
			ImageBuffer=ImageBuffer-i;
			for (uint k=0;k<NumberOfSections;k++)
			{
				Section_Copy(ImageBuffer,pe,sord(pe,k),ptrd(pe,k),va(pe,k));
			}
			fclose(fp);
			return ImageBuffer;
		}else 
		{
			printf("Not enough space for ImageBuffer");
			fclose(fp);
			return NULL;
		}
	}else return NULL;
}
//*******************************************************ImageBuffer -> NewBuffer
uchar* compress(uchar* ch)
{	
	uchar* NewBuffer;
	ushort NumberOfSections,SizeOfOptionalHeader;
	uint PE_add,PointerToRawData,SizeOfRawData,SizeOfHeaders,VirtualAddress;
	PE_add=*(uint*)(ch+0x3c);
	NumberOfSections=*(ushort*)(ch+PE_add+6);
	SizeOfOptionalHeader=*(ushort*)(ch+PE_add+20);
	PointerToRawData=*(uint*)(ch+PE_add+24+SizeOfOptionalHeader+20+(NumberOfSections-1)*40);
	SizeOfRawData=*(uint*)(ch+PE_add+24+SizeOfOptionalHeader+16+(NumberOfSections-1)*40);
	SizeOfHeaders=*(uint*)(ch+PE_add+84);
	NewBuffer=(uchar*)malloc(PointerToRawData+SizeOfRawData);
	if (NewBuffer!=NULL)
	{
		for (int k=0;k<PointerToRawData+SizeOfRawData;k++)
		{
			*NewBuffer=0;
			NewBuffer++;
		}
		NewBuffer=NewBuffer-(PointerToRawData+SizeOfRawData);
		for (int i=0;i<SizeOfHeaders;i++)
		{
			*NewBuffer=*ch;
			NewBuffer++;
			ch++;
		}
		ch=ch-SizeOfHeaders;
		NewBuffer=NewBuffer-SizeOfHeaders;
		for (int j=0;j<NumberOfSections;j++)
		{	
			VirtualAddress=*(uint*)(ch+PE_add+24+SizeOfOptionalHeader+12+j*40);
			PointerToRawData=*(uint*)(ch+PE_add+24+SizeOfOptionalHeader+20+j*40);
			SizeOfRawData=*(uint*)(ch+PE_add+24+SizeOfOptionalHeader+16+j*40);
			Section_Copy_0(ch,NewBuffer,VirtualAddress,PointerToRawData,SizeOfRawData);
		}
		return NewBuffer;
	}else 
	{
		printf("Not enough space for NewBuffer");
		return NULL;
	}
}
//*******************************************************//copy section(ImageBuffer -> NewBuffer)
uchar Section_Copy_0(uchar*image,uchar*New,uint add_image,uint add_new,uint size)
{
	image=image+add_image;
	New=New+add_new;
	for (int i=0;i<size;i++)
	{
		*New=*image;
		image++;
		New++;
	}
	return 0;
}
//************************************************judge whether there is enough space to add a section
uchar space_enough()
{
	FILE* fp;
	uint pe,PointerToRawData_first,SizeOfHeaders;
	ushort NumberOfSections,SizeOfOptionalHeader;
	pe=find_PE();
	fp=file_open();
	if (fp!=NULL)
	{
		SizeOfOptionalHeader=optional_size();
		NumberOfSections=section_num();
		SizeOfHeaders=header_size();
		PointerToRawData_first=ptrd(pe,0);
		if ((PointerToRawData_first-(pe+24+SizeOfOptionalHeader+40*NumberOfSections)) >= 80)
		{
			fclose(fp);
			return 1;
		}else if ((SizeOfHeaders-60-24-SizeOfOptionalHeader-40*NumberOfSections) >= 80)
		{
			fclose(fp);
			return 2;
		}else
		{
			printf("Not enough space to add a section");
			fclose(fp);
			return 0;
		}
	}else return 0;
}
//*************************************************write a section table
uchar sectiontable_write()
{
	FILE* fp;
	ushort NumberOfSections,SizeOfOptionalHeader;
	uint pe;
	uchar section_new[40]={0x2e,0x74,0x65,0x78,0x74,0x00,0x00,0x00,0x00,0x00,
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
					0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x60};
	fp=file_open();
	if (fp!=NULL)
	{
		if (space_enough())
		{
			pe=find_PE();
			NumberOfSections=section_num();
			SizeOfOptionalHeader=optional_size();
			fseek(fp,pe+24+SizeOfOptionalHeader+40*NumberOfSections,0);
			for (uint i=0;i<40;i++)
			{
				fputc(section_new[i],fp);
			}
			for (uint j=0;j<40;j++)
			{
				fputc(0,fp);
			}
		}else return 0;
		fclose(fp);
		return 1;
	}else return 0;
}
//*************************************************modify the NumberOfSections(+1)
uchar modify_section_num()
{
	FILE* fp;
	ushort NumberOfSections_new;
	NumberOfSections_new=section_num()+1;
	uint pe;
	fp=file_open();
	pe=find_PE();
	if (fp!=NULL)
	{
		fseek(fp,pe+6,0);
		fwrite(&NumberOfSections_new,2,1,fp);
	}else return 0;
	fclose(fp);
	return 1;
}
//*************************************************modify the SizeOfImage(+1000)
uchar modify_image_size()
{
	FILE* fp;
	uint pe,SizeOfImage_new;
	SizeOfImage_new=Image_size()+0x1000;
	fp=file_open();
	pe=find_PE();
	if (fp!=NULL)
	{
		fseek(fp,pe+80,0);
		fwrite(&SizeOfImage_new,4,1,fp);
	}else return 0;
	fclose(fp);
	return 1;
}
//***********************************************write a section
uchar section_write()
{
	FILE* fp;
	uint pe;
	uchar code[4096]={0x00};
	fp=file_open();
	pe=find_PE();
	if (fp!=NULL)
	{
		fseek(fp,0,2);
		fseek(fp,1,1);
		for (uint i=0;i<4096;i++)
		{
			fputc(code[i],fp);
		}
	}else return 0;
}
//***********************************************correcting section table properties
uchar sectiontable_correct()
{
	FILE* fp;
	ushort NumberOfSections,SizeOfOptionalHeader;
	uint pe,VirtualSize,VirtualAddress,SizeOfRawData,VirtualAddress_new,PointerToRawData,PointerToRawData_new;
	uint VirtualSize0,SizeOfRawData0;
	VirtualSize0=0x1000;
	SizeOfRawData0=0x1000;
	pe=find_PE();
	NumberOfSections=section_num();
	VirtualSize=vs(pe,NumberOfSections-1);
	VirtualAddress=va(pe,NumberOfSections-1);
	SizeOfRawData=sord(pe,NumberOfSections-1);
	PointerToRawData=ptrd(pe,NumberOfSections-1);
	SizeOfOptionalHeader=optional_size();
	if (VirtualSize>=SizeOfRawData)
	{
		VirtualAddress_new=VirtualAddress+VirtualSize;
	}else VirtualAddress_new=VirtualAddress+SizeOfRawData;
	PointerToRawData_new=PointerToRawData+SizeOfRawData;
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+24+SizeOfOptionalHeader+40*NumberOfSections+8,0);
		fwrite(&VirtualSize0,4,1,fp);
		fwrite(&VirtualAddress_new,4,1,fp);
		fwrite(&SizeOfRawData0,4,1,fp);
		fwrite(&PointerToRawData_new,4,1,fp);
	}else return 0;
	fclose(fp);
	return 1;
}
//******************************************************section table merge
uchar sectiontable_merge()
{
	FILE* fp;
	ushort SizeOfOptionalHeader,NumberOfSections;
	uint pe,SizeOfImage,VirtualAddress,VirtualSize,SizeOfRawData;
	pe=find_PE();
	SizeOfImage=Image_size();
	VirtualAddress=va(pe,0);
	VirtualSize=SizeOfRawData=SizeOfImage-VirtualAddress;
	SizeOfOptionalHeader=optional_size();
	NumberOfSections=1;
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+6,0);
		fwrite(&NumberOfSections,2,1,fp);
		fseek(fp,pe+24+SizeOfOptionalHeader+8,0);
		fwrite(&VirtualSize,4,1,fp);
		fseek(fp,pe+24+SizeOfOptionalHeader+16,0);
		fwrite(&SizeOfRawData,4,1,fp);
	}else return 0;
	fclose(fp);
	return 1;
}