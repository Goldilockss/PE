// PE.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <stdio.h>
#include <malloc.h>
#include "function.h"
FILE* file_open()
{
	FILE* fp=fopen("C:\\Users\\HP\\Desktop\\159.exe","r");
	return fp;
}
FILE* file_write()
{
	FILE* fn=fopen("C:\\Users\\HP\\Desktop\\123.exe","w");
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
			fread(ch,1,1,fp);
			ch++;
		}
	}else return 0;
	fclose(fp);
	return 1;
}
//*****************************************************copy Header insert section
uchar* stretching(uint pe)
{
	FILE* fp;
	uchar* ImageBuffer;
	fp=file_open();
	if (fp!=NULL)
	{
		ushort NumberOfSections;
		uint SizeOfHeaders,SizeOfImage;
		fseek(fp,pe+6,0);
		fread(&NumberOfSections,2,1,fp);
		fseek(fp,pe+80,0);
		fread(&SizeOfImage,4,1,fp);
		fseek(fp,pe+84,0);
		fread(&SizeOfHeaders,4,1,fp);
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
				*ImageBuffer=fgetc(fp);
				ImageBuffer++;
			}
			ImageBuffer=ImageBuffer-i;
			for (uint k=0;k<NumberOfSections;k++)
			{
				Section_Copy(ImageBuffer,pe,ptrd(pe,k),sord(pe,k),va(pe,k));
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
//*******************************************************
uchar Section_Copy_0(uchar*image,uchar*New,uint add_image,uint add_new,uint size)//copy section(ImageBuffer -> NewBuffer)
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
//*******************************************************file to internal storage
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
		NewBuffer=NewBuffer-PointerToRawData+SizeOfRawData;
		for (int i=0;i<SizeOfHeaders;i++)
		{
			*NewBuffer=*ch;
			NewBuffer++;
			ch++;
		}
		ch=ch-SizeOfHeaders;
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
//*************************************************size of NewBuffer
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

