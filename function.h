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
int find_PE();
char* store_PE(int pe);
int pri_Section(int pe);
uint ptrd(int pe,char num);
uint va(int pe,char num);
uint sord(int pe,char num);
uchar Section_Copy(uchar* ch,int pe,uint size,uint add_file,uint add_image);
uchar* stretching(int pe);
#endif
 