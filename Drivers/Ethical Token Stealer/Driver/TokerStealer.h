#pragma once


#define DRIVER_PREFIX "[+] From TokenStealer:  "

#define IOCTL_CHANGE_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2000, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct Data {
	ULONG ProcessId;
};