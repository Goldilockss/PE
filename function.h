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

FILE* file_open();
int find_PE();
char* store_PE(int pe);
int pri_Section(int pe);
uint ptrd(int pe,char num);
uint va(int pe,char num);
uint sord(int pe,char num);
uchar Section_Copy(uchar* ch,int pe,uint size,uint add,char num);
uchar* stretching(int pe);
#endif
 