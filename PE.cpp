// PE.cpp : Defines the entry point for the console application.
//
//*****************************************************
#include "stdafx.h"
#include <stdio.h>
#include <malloc.h>
#include "function.h"
int main(int argc, char* argv[])
{
	uint a,b;
	//space_enough();
	//modify_image_size();
	//section_write();
	//sectiontable_write();
	//sectiontable_correct();
	//modify_section_num();
	//section_merge();
	//export_pri();
	//relocation_pri();
	//export_move_complete();
	//import_pri();
	//section_add();
	ImportInject();
	return 0;
}
