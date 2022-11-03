// PE.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <stdio.h>
#include <malloc.h>
#include "function.h"
FILE* file_open()
{
	FILE* fp=fopen("C:\\Users\\HP\\Desktop\\testdll.dll","rb+");
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
		if ((a=='M') && (b=='Z'))			//judge whether MZ starts
		{
			fseek(fp,60L,0);
			pe=fgetc(fp);
			fseek(fp,pe,0);
			a=fgetc(fp);
			b=fgetc(fp);
			if ((a=='P') && (b=='E'))		//judge whether there is PE mark
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
//****************************************************FileBuffer get VirtualSize
uint vs(uchar num)
{
	FILE* fp;
	ushort SizeOfOptionalHeader;
	uint pe,VirtualSize;
	pe=find_PE();
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
uint ptrd(uchar num)
{
	FILE* fp;
	ushort SizeOfOptionalHeader;
	uint pe,PointerToRawData;
	pe=find_PE();
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
uint va(uchar num)
{
	FILE* fp;
	ushort SizeOfOptionalHeader;
	uint pe,VirtualAddress;
	pe=find_PE();
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
uint sord(uchar num)
{
	FILE* fp;
	ushort SizeOfOptionalHeader;
	uint pe,SizeOfRawData;
	pe=find_PE();
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
	ch=ch+add_image;			//offset to momery
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,add_file,0);	//offset to file
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
	return PointerToRawData+SizeOfRawData;		//last PointerToRawData+last SizeOfRawData
}
//***********************************************FileBuffer get SizeOfImage
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
//***********************************************FileBuffer get AddressOfEntryPoint
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
//***************************************************FileBuffer get SizeOfOptionalHeader
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
//****************************************************FileBuffer get SizeOfHeaders
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
//***************************************************FileBuffer get NumberOfSections
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
uchar* stretching()
{
	FILE* fp;
	uchar* ImageBuffer;
	uint pe;
	pe=find_PE();
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
			for (uint j=0;j<SizeOfImage;j++)		//initialize to all zeros
			{
				*ImageBuffer=0;
				ImageBuffer++;
			}
			ImageBuffer=ImageBuffer-SizeOfImage;	//the pointer returns to the beginning
			fseek(fp,0,0);							//the cursor returns to the beginning
			for (uint i=0;i<SizeOfHeaders;i++)		//copy header and section table
			{
				fread(ImageBuffer,1,1,fp);
				ImageBuffer++;
			}
			ImageBuffer=ImageBuffer-i;				//the pointer returns to the beginning
			for (uint k=0;k<NumberOfSections;k++)	//circular copy section
			{
				Section_Copy(ImageBuffer,pe,sord(k),ptrd(k),va(k));
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
		for (int k=0;k<PointerToRawData+SizeOfRawData;k++)		//initialize to all zeros
		{
			*NewBuffer=0;
			NewBuffer++;
		}
		NewBuffer=NewBuffer-(PointerToRawData+SizeOfRawData);	//the pointer returns to the beginning
		for (int i=0;i<SizeOfHeaders;i++)						//copy header and section table
		{
			*NewBuffer=*ch;
			NewBuffer++;
			ch++;
		}
		ch=ch-SizeOfHeaders;									//the pointer returns to the beginning
		NewBuffer=NewBuffer-SizeOfHeaders;						//the pointer returns to the beginning
		for (int j=0;j<NumberOfSections;j++)					//circular copy section
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
	image=image+add_image;						//offset to image
	New=New+add_new;							//offset to new
	for (int i=0;i<size;i++)
	{
		*New=*image;
		image++;
		New++;
	}
	return 0;
}
//************************************************judge whether there is enough space to add a section(FileBuffer)
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
		PointerToRawData_first=ptrd(0);
		if ((PointerToRawData_first-(pe+24+SizeOfOptionalHeader+40*NumberOfSections)) >= 80)//first PointerToRawData-last section table
		{
			fclose(fp);
			return 1;
		}else if ((SizeOfHeaders-60-24-SizeOfOptionalHeader-40*NumberOfSections) >= 80)//move NT header and section table up to cover useless data
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
			fseek(fp,pe+24+SizeOfOptionalHeader+40*NumberOfSections,0);//write after the last section table
			for (uint i=0;i<40;i++)
			{
				fputc(section_new[i],fp);
			}
			for (uint j=0;j<40;j++)										//add 40 zeros
			{
				fputc(0,fp);
			}
		}else return 0;
		fclose(fp);
		return 1;
	}else return 0;
}
//*************************************************modify the NumberOfSections(+1)(FileBuffer)
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
//*************************************************modify the SizeOfImage(+1000)(FileBuffer)
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
		fseek(fp,0,2);				//move cursor to end of file
		fseek(fp,1,1);				//start a new line
		for (uint i=0;i<4096;i++)
		{
			fputc(code[i],fp);
		}
		return 1;
	}else return 0;
}
//***********************************************correcting section table properties(add a section)
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
	VirtualSize=vs(NumberOfSections-1);
	VirtualAddress=va(NumberOfSections-1);
	SizeOfRawData=sord(NumberOfSections-1);
	PointerToRawData=ptrd(NumberOfSections-1);
	SizeOfOptionalHeader=optional_size();
	if (VirtualSize>=SizeOfRawData)		//calculate new section's VirtualAddress(last VirtualAddress+size)
	{
		VirtualAddress_new=VirtualAddress+VirtualSize;
	}else VirtualAddress_new=VirtualAddress+SizeOfRawData;
	PointerToRawData_new=PointerToRawData+SizeOfRawData;//last PointerToRawData+last SizeOfRawData
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
//******************************************************section merge parameter modification
uchar* sectionmerge_modify(uchar* ch)
{
	if (ch!=NULL)
	{
		ushort SizeOfOptionalHeader,NumberOfSections;
		uint pe,SizeOfImage,VirtualAddress,VirtualSize,SizeOfRawData,Characteristics,Characteristics_new;	
		pe=*(uint*)(ch+0x3c);
		NumberOfSections=*(ushort*)(ch+pe+6);
		SizeOfOptionalHeader=*(ushort*)(ch+pe+20);
		Characteristics_new=*(uint*)(ch+pe+24+SizeOfOptionalHeader+36);
		for (int i=0;i<NumberOfSections;i++)		//all section attributes or operations
		{
			Characteristics=*(uint*)(ch+pe+24+SizeOfOptionalHeader+36+i*40);
			Characteristics_new=Characteristics_new|Characteristics;
		}
		NumberOfSections=1;
		*(ushort*)(ch+pe+6)=NumberOfSections;
		VirtualAddress=*(uint*)(ch+pe+24+SizeOfOptionalHeader+12);
		SizeOfImage=*(uint*)(ch+pe+80);
		VirtualSize=SizeOfRawData=SizeOfImage-VirtualAddress;	//the combined size of all sections(SizeOfImage-last VirtualAddress)
		*(uint*)(ch+pe+24+SizeOfOptionalHeader+8)=VirtualSize;
		*(uint*)(ch+pe+24+SizeOfOptionalHeader+16)=SizeOfRawData;
		*(uint*)(ch+pe+24+SizeOfOptionalHeader+36)=Characteristics_new;
	}else return NULL;
	return ch;
}
//****************************************************section merge
uchar section_merge()
{
	uchar* ImageBuffer;
	uchar* NewBuffer;
	ImageBuffer=stretching();			//stretching
	sectionmerge_modify(ImageBuffer);	//section table amendment
	NewBuffer=compress(ImageBuffer);	//compress
	file_out(NewBuffer,NewBuffer_size(NewBuffer));//output file
	return 1;
}
//***************************************************RVA -> FOA
uint RVA_FOA(uint add)
{
	ushort NumberOfSections,section_which;
	uint VirtualAddress,SizeOfHeaders,PointerToRawData,SizeOfRawData;
	NumberOfSections=section_num();
	SizeOfHeaders=header_size();
	if (add>=va(0))											//whether before the first section
	{
		if (add<va(NumberOfSections-1))					//whether in the last section
		{
			for (int i=0;i<NumberOfSections;i++)			//loop judgment between which two section
			{
				if ((add>=va(i)) && (add<va(i+1)))
				{
					section_which=i;
					break;
				}
			}
		}else
		{
			if((add-va(NumberOfSections-1))<=sord(NumberOfSections-1))//whether to add zeros for memory alignment
			{
				//printf("In last section\n");
				PointerToRawData=ptrd(NumberOfSections-1);
				return PointerToRawData+(add-va(NumberOfSections-1));
			}else
			{
				//printf("Zero filling to align memory\n");
				return 0;
			}
		}
	}else
	{
		if (add<=SizeOfHeaders)										//whether to add zeros for memory alignment
		{
			//printf("Not in section\n");
			return add;
		}else
		{
			//printf("Zero filling to align memory\n");
			return 0;
		}
	}
	if ((add-va(section_which))<=sord(section_which))			//whether to add zeros for memory alignment
	{
		//printf("In No.%d section\n",section_which+1);
		PointerToRawData=ptrd(section_which);
		return PointerToRawData+(add-va(section_which));
	}else
	{
		//printf("Zero filling to align memory\n");
		return 0;
	}
}
//****************************************************get address of export
uint export_add()
{
	FILE* fp;
	uint pe,VirtualAddress;
	pe=find_PE();
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+24+96,0);
		fread(&VirtualAddress,4,1,fp);
		if (VirtualAddress!=0)
		{	
			fclose(fp);
			return VirtualAddress;
		}else
		{
			printf("No export\n");
			fclose(fp);
			return 0;
		}
	}else return 0;
}
//***********************************************get address of import
uint import_add()
{
	FILE* fp;
	uint pe,VirtualAddress;
	pe=find_PE();
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+24+104,0);
		fread(&VirtualAddress,4,1,fp);
		if (VirtualAddress!=0)
		{	
			fclose(fp);
			return VirtualAddress;
		}else
		{
			printf("No import\n");
			fclose(fp);
			return 0;
		}
	}else return 0;
}
//***********************************************get address of relocation
uint relocation_add()
{
	FILE* fp;
	uint pe,VirtualAddress;
	pe=find_PE();
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,pe+24+136,0);
		fread(&VirtualAddress,4,1,fp);
		if (VirtualAddress!=0)
		{	
			fclose(fp);
			return VirtualAddress;
		}else
		{
			printf("No relocation\n");
			fclose(fp);
			return 0;
		}
	}else return 0;
}
//***********************************************printf export table
uchar export_pri()
{
	FILE* fp;
	ushort ordinals;
	uint pe,AddressOfNames,VirtualAddress_ex,NumberOfNames,name_add,
		ch,AddressOfNameOrdinals,AddressOfFunctions,NumberOfFunctions,function_add;
	VirtualAddress_ex=export_add();
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,RVA_FOA(VirtualAddress_ex)+32,0);
		fread(&AddressOfNames,4,1,fp);
		fseek(fp,RVA_FOA(VirtualAddress_ex)+24,0);
		fread(&NumberOfNames,4,1,fp);
		printf("Names:\n");
		for (int i=0;i<NumberOfNames;i++)
		{
			fseek(fp,RVA_FOA(AddressOfNames)+i*4,0);
			fread(&name_add,4,1,fp);
			fseek(fp,name_add,0);
			printf("%8x ",name_add);
			do									//printf names
			{
				ch=fgetc(fp);
				printf("%c",ch);
			}while(ch!=0);
			printf("\n");
		}
		//**************************************
		fseek(fp,RVA_FOA(VirtualAddress_ex)+36,0);
		fread(&AddressOfNameOrdinals,4,1,fp);
		printf("Ordinals:\n");
		for (int j=0;j<NumberOfNames;j++)		//printf ordinals
		{
			fseek(fp,AddressOfNameOrdinals+j*2,0);
			fread(&ordinals,2,1,fp);
			printf("%4x\n",ordinals);
		}
		//**************************************
		fseek(fp,RVA_FOA(VirtualAddress_ex)+20,0);
		fread(&NumberOfFunctions,4,1,fp);
		fseek(fp,RVA_FOA(VirtualAddress_ex)+28,0);
		fread(&AddressOfFunctions,4,1,fp);
		printf("Functions:\n");
		for (int k=0;k<NumberOfFunctions;k++)	//printf functions
		{
			fseek(fp,RVA_FOA(AddressOfFunctions)+k*4,0);
			fread(&function_add,4,1,fp);
			printf("%8x\n",function_add);
		}
	}else return 0;
	fclose(fp);
	return 1;
}
//*************************************************printf relocation
uchar relocation_pri()
{
	FILE* fp;
	ushort modify_add;
	uint VirtualAddress_rel,VirtualAdress_block,SizeOfBlock;
	VirtualAddress_rel=relocation_add();
	fp=file_open();
	if (fp!=NULL)
	{
		fseek(fp,RVA_FOA(VirtualAddress_rel),0);
		fread(&VirtualAdress_block,4,1,fp);
		printf("Relocation:\n");
		for (;VirtualAdress_block!=0;)			//printf block
		{
			fread(&SizeOfBlock,4,1,fp);
			printf("%8x\n",VirtualAdress_block);
			for (int i=0;i<(SizeOfBlock-8)/2;i++)
			{
				fread(&modify_add,2,1,fp);
				printf("%4x\n",VirtualAdress_block+(modify_add-0x3000));
			}
			fread(&VirtualAdress_block,4,1,fp);
		}
	}else return 0;
	fclose(fp);
	return 1;
}
//************************************************export table move
uchar export_move()
{
	FILE* fp;
	uchar ch;
	ushort NumberOfSections,ordinals;
	uint pe,PointerToRawData,VirtualAddress_ex,AddressOfFunctions,function_add,NumberOfFunctions,
		NumberOfNames,AddressOfNameOrdinals,name_add,AddressOfNames,
		AddressOfFunctions_new,AddressOfName_new,AddressOfNameOrdinals_new,name_add_new;
	pe=find_PE();
	NumberOfSections=section_num();
	PointerToRawData=ptrd(NumberOfSections-1);
	fp=file_open();
	if (fp!=NULL)
	{
		VirtualAddress_ex=export_add();
		for (int i=0;i<40;i++)			//move export
		{
			fseek(fp,RVA_FOA(VirtualAddress_ex)+i,0);
			ch=fgetc(fp);
			fseek(fp,PointerToRawData+i,0);
			fputc(ch,fp);
		}
		//*************************************
		fseek(fp,RVA_FOA(VirtualAddress_ex)+20,0);
		fread(&NumberOfFunctions,4,1,fp);
		fseek(fp,RVA_FOA(VirtualAddress_ex)+28,0);
		fread(&AddressOfFunctions,4,1,fp);
		for (int j=0;j<NumberOfFunctions;j++)	//move functions
		{
			fseek(fp,RVA_FOA(AddressOfFunctions)+j*4,0);
			fread(&function_add,4,1,fp);
			fseek(fp,PointerToRawData+40+j*4,0);
			fwrite(&function_add,4,1,fp);
		}
		//*************************************
		fseek(fp,RVA_FOA(VirtualAddress_ex)+24,0);
		fread(&NumberOfNames,4,1,fp);
		fseek(fp,RVA_FOA(VirtualAddress_ex)+36,0);
		fread(&AddressOfNameOrdinals,4,1,fp);
		for (int k=0;k<NumberOfNames;k++)	//move ordinals
		{
			fseek(fp,AddressOfNameOrdinals+k*2,0);
			fread(&ordinals,2,1,fp);
			fseek(fp,PointerToRawData+40+NumberOfFunctions*4+k*2,0);
			fwrite(&ordinals,2,1,fp);
		}
		//*************************************
		fseek(fp,RVA_FOA(VirtualAddress_ex)+32,0);
		fread(&AddressOfNames,4,1,fp);
		for (int m=0;m<NumberOfNames;m++)	//move name_add
		{
			fseek(fp,RVA_FOA(AddressOfNames)+m*4,0);
			fread(&name_add,4,1,fp);
			fseek(fp,PointerToRawData+40+NumberOfFunctions*4+NumberOfNames*2+m*4,0);
			fwrite(&name_add,4,1,fp);
		}
		//*************************************
		uchar num=0;
		for (int n=0;n<NumberOfNames;n++)	//move name
		{
			fseek(fp,RVA_FOA(AddressOfNames)+n*4,0);
			fread(&name_add,4,1,fp);
			fseek(fp,name_add,0);
			do								
			{
				ch=fgetc(fp);
				fseek(fp,PointerToRawData+40+NumberOfFunctions*4+NumberOfNames*2+NumberOfNames*4+num,0);
				fputc(ch,fp);
				num++;
				fseek(fp,name_add+num,0);
			}while(ch!=0);
			num=0;
		}
		//************************************
		fseek(fp,pe+24+96,0);	//correct VirtualAddress_ex
		fwrite(&PointerToRawData,4,1,fp);
		AddressOfFunctions_new=PointerToRawData+40;	//corect AddressOfFunctions
		fseek(fp,PointerToRawData+28,0);
		fwrite(&AddressOfFunctions_new,4,1,fp);	
		AddressOfName_new=PointerToRawData+40+4*NumberOfFunctions+2*NumberOfNames;	//correct AddressOfName
		fseek(fp,PointerToRawData+32,0);
		fwrite(&AddressOfName_new,4,1,fp);	
		AddressOfNameOrdinals_new=PointerToRawData+40+4*NumberOfFunctions;	//correct AddressOfNameOrdinals
		fseek(fp,PointerToRawData+36,0);
		fwrite(&AddressOfNameOrdinals_new,4,1,fp);
		fseek(fp,PointerToRawData+40+4*NumberOfFunctions+2*NumberOfNames,0);	//correct first name_add
		name_add_new=PointerToRawData+40+4*NumberOfFunctions+2*NumberOfNames+4*NumberOfNames;
		fwrite(&name_add_new,4,1,fp);
		for (int x=0;x<NumberOfNames-1;x++)	//correct remaining name_add
		{
			int y=0;
			do
			{
				fseek(fp,PointerToRawData+40+4*NumberOfFunctions+2*NumberOfNames+4*NumberOfNames+y,0);
				ch=fgetc(fp);
				y++;
			}while(ch!=0);
			name_add_new=PointerToRawData+40+4*NumberOfFunctions+2*NumberOfNames+4*NumberOfNames+y;
			fseek(fp,PointerToRawData+40+4*NumberOfFunctions+2*NumberOfNames+4*(x+1),0);
			fwrite(&name_add_new,4,1,fp);
		}
	}else return 0;
	fclose(fp);
	return 1;
}
//****************************************************create a new section and move the export table
uchar export_move_complete()
{
	sectiontable_write();	//write a blank section table
	section_write();	//write a blank section
	sectiontable_correct();	//revised section table data
	modify_section_num();	//revised NumberOfSections
	modify_image_size();	//revised SizeOfImage
	export_move();	//move export table
	return 1;
}