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
uint ptrd(uchar num);
uint va(uchar num);
uint sord(uchar num);
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
uint vs(uchar num);
uchar sectiontable_correct();
uchar* sectionmerge_modify(uchar* ch);
uchar section_merge();
uint header_size();
uint RVA_FOA(uint add);
uint export_add();
uint import_add();
#endif
 