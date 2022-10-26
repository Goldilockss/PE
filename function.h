#ifndef _function_H_
#define _function_H_
#include "stdafx.h"
#include <stdio.h>

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef uint 
#define uint unsigned int
#endif

#ifndef ushort
#define ushort unsigned short
#endif

FILE* file_open();
FILE* file_write();
uint find_PE();
uchar* store_PE(uint pe);
uint pri_Section(uint pe);
uint ptrd(uint pe,char num);
uint va(uint pe,char num);
uint sord(uint pe,char num);
uchar Section_Copy(uchar* ch,uint pe,uint size,uint add_file,uint add_image);
uchar* stretching(uint pe);
uchar Section_Copy_0(uchar*image,uchar*New,uint add_image,uint add_new,uint size);
uchar file_out(uchar* ch,uint size);
uchar* compress(uchar* ch);
uint NewBuffer_size(uchar* ch);
uint Image_size(uint pe);
uint EntryPoint_add(uint pe);
uchar space_enough();
uchar sectiontable_write();
uchar modify_section_num();
uchar modify_image_size();
uchar section_write();
#endif
 