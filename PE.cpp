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
	space_enough();
	return 0;
}