#pragma once
#include "includes.h"

template <typename T>
class srop_class {
public:

	T* data;
	srop_class(T* info) : data(info) {

	}
	~srop_class() {
		free(data);
	}

	DWORD findThreadForHijacking();
	DWORD CreateSharedSectionWithPayload();
	PVOID CreateSharedSection();
	DWORD CreateROP();
	DWORD Start();

};

