// PE.cpp : Defines the entry point for the console application.
//
//*****************************************************
#include "stdafx.h"
#include <stdio.h>
#include <malloc.h>
#include "function.h"
int main(int argc, char* argv[])
{
	uint pe_add,size;
	pe_add=find_PE();
	/*
	image=stretching(pe_add);
	New=compress(image);
	size=NewBuffer_size(image);
	file_out(New,size);*/
	//space_enough();
	//modify_image_size();
	//section_write();
	//sectiontable_write();
	//sectiontable_correct();
	//modify_section_num();
	section_merge();
	return 0;
}