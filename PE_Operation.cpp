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
	uchar NumberOfSections,SizeOfOptionalHeader;
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
//****************************************************get PointerToRawData
uint ptrd(int pe,char num)
{
	FILE* fp;
	uchar SizeOfOptionalHeader;
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
//***************************************************get VirtualAddress
uint va(int pe,char num)
{
	FILE* fp;
	uchar SizeOfOptionalHeader;
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
//****************************************************get SizeOfRawData
uint sord(int pe,char num)
{
	FILE* fp;
	uchar SizeOfOptionalHeader;
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
//**************************************************copy section
uchar Section_Copy(uchar* ch,int pe,uint size,uint add,char num)
{
	uchar SizeOfOptionalHeader;
	FILE* fp;
	ch=ch+add;
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+20,0);
		fread(&SizeOfOptionalHeader,2,1,fp);
		fseek(fp,pe+24+SizeOfOptionalHeader+num*40,0);
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
	uchar* ch;
	fp=file_open();
	if (fp!=NULL)
	{
		uchar NumberOfSections;
		uint SizeOfHeaders,SizeOfImage;
		fseek(fp,pe+6,0);
		fread(&NumberOfSections,2,1,fp);
		fseek(fp,pe+80,0);
		fread(&SizeOfImage,4,1,fp);
		fseek(fp,pe+84,0);
		fread(&SizeOfHeaders,4,1,fp);
		ch=(uchar*)malloc(SizeOfImage);
		if (ch!=NULL)
		{
			for (uint j=0;j<SizeOfImage;j++)
			{
				*ch=0;
				ch++;
			}
			ch=ch-SizeOfImage;
			fseek(fp,0,0);
			for (uint i=0;i<SizeOfHeaders;i++)
			{
				*ch=fgetc(fp);
				ch++;
			}
			ch=ch-i;
			for (uint k=0;k<NumberOfSections;k++)
			{
				Section_Copy(ch,pe,sord(pe,k),va(pe,k),k);
			}
			fclose(fp);
			return ch;
		}else 
		{
			printf("Not enough space");
			return NULL;
		}
	}else return NULL;
}
//*******************************************************file to internal storage
uint compress(uchar* ch,int pe)
{	
	FILE* fp;
	FILE* fpo;
	fpo=file_open();
	fp=fopen("C:\\Users\\HP\\Desktop\\test.txt","w");
	if ((fp!=NULL) && (fpo!=NULL))
	{
		int arr_data[10]=0;
		int space=0;
		uchar NumberOfSections;
		uint SizeOfHeaders,SizeOfImage,PointerToRawData;
		fseek(fp,pe+84,0);
		fread(&SizeOfHeaders,4,1,fp);
		fseek(fp,pe+6,0);
		fread(&NumberOfSections,2,1,fp);
		for (uint j=0;j<NumberOfSections,j++)
		{
			arr_data[j]=sord(pe,j);
		}
		space=space+SizeOfHeaders;
		for (uint k=0;k<10;k++)
		{
			space=space+arr_data[k];
		}
		for (uint i=0;i<space;i++)
		{
		}
	}else return 0;
	return 0;
}

