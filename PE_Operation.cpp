// PE.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <stdio.h>
#include <malloc.h>
#include "function.h"
FILE* file_open()
{
	FILE* fp=fopen("C:\\Users\\HP\\Desktop\\1595756543VideoCap(2).exe","r");
	return fp;
}
FILE* file_write()
{
	FILE* fn=fopen("C:\\Users\\HP\\Desktop\\123.txt","w");
	return fn;
}
//******************************************************find the "PE"
int find_PE()
{
	FILE* fp;
	fp=file_open();
	if (fp!=NULL)
	{
		char a,b;
		int pe;
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
		}
	}else return -1;
}
//*****************************************************save standard PE head
char* store_PE(int pe)
{
	char* ch;
	FILE* fp;
	fp=file_open();
	if (fp!=NULL)
	{
		ch=(char*)malloc(28);
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
int pri_Section(int pe)
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
	}else return -1;
}
//****************************************************
//****************************************************FileBuffer get PointerToRawData
uint ptrd(int pe,char num)
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
		return PointerToRawData;
	}else return 0;
}
//***************************************************FileBuffer get VirtualAddress
uint va(int pe,char num)
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
		return VirtualAddress;
	}else return 0;
}
//****************************************************FileBuffer get SizeOfRawData
uint sord(int pe,char num)
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
		return SizeOfRawData;
	}
}
//**************************************************copy section(FileBuffer -> ImageBuffer)
uchar Section_Copy(uchar* ch,int pe,uint size,uint add_file,uint add_image)
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
}
//*****************************************************copy Header insert section
uchar* stretching(int pe)
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
//*******************************************************file to internal storage
uchar* compress(uchar* ch)
{	
	uchar* NewBuffer;
	ushort NumberOfSections,SizeOfOptionalHeader;
	uint PE_add,PointerToRawData,SizeOfRawData,SizeOfHeaders,VirtualAddress;
	PE_add=*(uint*)(ch+0x3c);
	NumberOfSections=*(ushort*)(ch+PE_add+6);
	SizeOfOptionalHeader=*(ushort*)(ch+PE_add+20);
	PointerToRawData=*(uint*)(ch+PE_add+24+SizeOfOptionalHeader+20+NumberOfSections*40);
	SizeOfRawData=*(uint*)(ch+PE_add+24+SizeOfOptionalHeader+16+NumberOfSections*40);
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

