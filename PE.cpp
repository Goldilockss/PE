// PE.cpp : Defines the entry point for the console application.
//
//*****************************************************
#include "stdafx.h"
#include <stdio.h>
#include <malloc.h>
#include "function.h"
int main(int argc, char* argv[])
{
	int flag;
	uchar* ch;
	flag=find_PE();
	ch=stretching(flag);
	for (int i=0;i<1000;i++)
	{
		printf("%02x ",*ch);
		ch++;
	}
	//ch1=store_PE(flag);
	//printf("%X",*ch1);
	//pri_jiebiao(flag);
	return 0;
}