#include <ntifs.h>
#include <ntddk.h>

#define PROCESS_VM_WRITE 0x0020
#define PROCESS_VM_OPERATION 0x0008
#define PATHNUM 18
PVOID g_CallbackHandle = NULL;

HANDLE processId = NULL; HANDLE pid;

HANDLE internalPid = NULL;

UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ExternalDriver");

char MODE_NUM = 0;
// MODE_NUM 0  normal mode
// MODE_NUM 1  focus mode

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

HANDLE Get_pid_from_name() {

	NTSTATUS status = STATUS_SUCCESS;
	ULONG bufferSize = 0;
	PVOID buffer = NULL;

	PSYSTEM_PROCESS_INFORMATION pCurrent = NULL;

	UNICODE_STRING processName;
	RtlInitUnicodeString(&processName, L"Palworld-Win64-Shipping.exe");
	//RtlInitUnicodeString(&processName, L"Palworld.exe");

	status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);  // ���⼭ �Ϻη� ���� ũ�⸦ Ʋ���� bufferSize �� �ʿ��� ũ�Ⱑ ��ܼ� �´�.
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'MDMP');   // �ش� bufferSize ��ŭ �Ҵ�
		if (buffer == NULL) {
			DbgPrint( "[ERROR : DRIVER] buffer �Ҵ� ���� \n");
			return pCurrent;
		}
		else {
			status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);   // ��¥ ��������
			if (!NT_SUCCESS(status)) {
				DbgPrint("[ERROR : DRIVER] ����� ���μ����� �������� �ʽ��ϴ�. \n");
				ExFreePoolWithTag(buffer, 'MDMP');
				return pCurrent;
			}
		}
	}


	DbgPrint("[INF : DRIVER] ����� ���μ��� Ȯ�� �Ϸ� \n");



	pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
	while (pCurrent) {
		if (pCurrent->ImageName.Buffer != NULL) {
			if (RtlCompareUnicodeString(&(pCurrent->ImageName), &processName, TRUE) == 0) {
				DbgPrint("[INF : DRIVER] ����� PID = %d \n ", pCurrent->ProcessId);
				ExFreePoolWithTag(buffer, 'MDMP');
				return pCurrent->ProcessId;
			}
		}
		if (pCurrent->NextEntryOffset == 0) {
			pCurrent = NULL;
		}
		else {
			pCurrent = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pCurrent) + pCurrent->NextEntryOffset);
		}
	}



	return pCurrent;
}


NTSTATUS SeLocateProcessImageName(
	PEPROCESS       Process,
	PUNICODE_STRING* pImageFileName
);

UNICODE_STRING SYSTEM32_PATH;

void SetSystem32Path(PCWSTR cDriverName) {
	RtlInitUnicodeString(&SYSTEM32_PATH, cDriverName);

	DbgPrint("[INF : DRIVER] C����̹� ���� ���� �Ϸ� : %ws \n", cDriverName);
	DbgPrint("[INF : DRIVER] �������� ���� : %wZ \n ", &SYSTEM32_PATH);

}

void InitSystem32Path() {
	PCWSTR cDriverName = L"\\Device\\HarddiskVolume3\\Windows\\System32\\";
	RtlInitUnicodeString(&SYSTEM32_PATH, cDriverName);
}


BOOLEAN IsInSystem32Directory(PUNICODE_STRING processName) {

	if (&SYSTEM32_PATH == NULL || !MmIsAddressValid(&SYSTEM32_PATH)) {
		DbgPrint("SYSTEM32_PATH is invalid.\n");
		return FALSE;
	}

	if (processName == NULL || !MmIsAddressValid(processName)) {
		DbgPrint("processName is invalid.\n");
		return FALSE;
	}

	//DbgPrint("[INF : DRIVER] SYSTEM32_PATH : %wZ \n ", &SYSTEM32_PATH);
	//DbgPrint("[INF : DRIVER] processName : %wZ \n ", processName);

	if (RtlPrefixUnicodeString(&SYSTEM32_PATH, processName, TRUE)) {
		return TRUE;
	}
	return FALSE;
}

#define WHITELIST_SIZE 6 // ȭ��Ʈ����Ʈ ũ�� ����
UNICODE_STRING whiteListE[WHITELIST_SIZE];

void InitializeWhiteListExternal() {
	RtlInitUnicodeString(&whiteListE[0], L"steamservice.exe");
	RtlInitUnicodeString(&whiteListE[1], L"GameOverlayUI.exe");
	RtlInitUnicodeString(&whiteListE[2], L"steam.exe");
	RtlInitUnicodeString(&whiteListE[3], L"Palworld-Win64-Shipping.exe");
	RtlInitUnicodeString(&whiteListE[4], L"Palworld.exe");
	RtlInitUnicodeString(&whiteListE[5], L"MsMpEng.exe");
	//RtlInitUnicodeString(&whiteListE[6], L"GameBarFTServer.exe");
	//RtlInitUnicodeString(&whiteListE[8], L"Discord.exe");

}


BOOLEAN IsInWhiteList(PUNICODE_STRING processName) {

	USHORT i;
	for (i = processName->Length / sizeof(WCHAR); i > 0; i--) {
		if (processName->Buffer[i - 1] == L'\\') {
			break;
		}
	}

	// ���� �̸� �κ��� ���� �ּҸ� ����
	PWCHAR fileNameStart = &processName->Buffer[i];

	// ���� �̸��� UNICODE_STRING���� ����
	UNICODE_STRING fileName;
	RtlInitUnicodeString(&fileName, fileNameStart);

	// ����� ���� �̸� ���
	DbgPrint("����� ���� �̸�: %wZ\n", &fileName);

	// ȭ��Ʈ����Ʈ�� ��
	for (int t = 0; t < WHITELIST_SIZE; t++) {
		if (RtlEqualUnicodeString(&whiteListE[t], &fileName, TRUE)) {
			return TRUE; // ȭ��Ʈ����Ʈ�� �ִ� ���
		}
	}

	return FALSE; // ȭ��Ʈ����Ʈ�� ���� ���
}




OB_PREOP_CALLBACK_STATUS PreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {

	UNREFERENCED_PARAMETER(RegistrationContext);
	// �����Ϸ��� ����� ���μ������� Ȯ��
	if (OperationInformation->ObjectType == *PsProcessType) {
		PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;

		// Ư�� ���μ����� ���� �ڵ� ������ ���� -> FindProcessByName �Լ��� ������ pid ��
		if (PsGetProcessId(targetProcess) == pid) {

			PEPROCESS currentProcess = PsGetCurrentProcess();  // �ڵ鿡 ������ ���μ���
			PUNICODE_STRING currentProcessName = NULL;

			SeLocateProcessImageName(currentProcess, &currentProcessName);



			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {   // �̰� �����ϼ���

				DbgPrint("[INF : DRIVER] ����� �ڵ� ���� :  %wZ\n", currentProcessName); // ���μ��� �̸� ���
				if (currentProcess == targetProcess || IsInWhiteList(currentProcessName)) {
					DbgPrint("[INF : DRIVER] �ŷڼ��ִ� ����� ���μ��� >>> handle �������\n");
					return OB_PREOP_SUCCESS;
				}

				if (IsInSystem32Directory(currentProcessName)) {
					DbgPrint("[INF : DRIVER] �ý��� ���μ��� >>> handle �������\n");
					return OB_PREOP_SUCCESS;

				}
				else {  // ����� ���μ��� �ε� ȭ��Ʈ����Ʈ�� ����

					ULONG desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
					DbgPrint("[INF : DRIVER] ���ΰ� ����� ���μ��� ��û�� ���� : 0x%X\n", desiredAccess);
					if ((desiredAccess & PROCESS_VM_WRITE) ||
						(desiredAccess & PROCESS_VM_OPERATION) ||
						(desiredAccess & PROCESS_DUP_HANDLE)) {

						// ���� ���� ���� ����
						OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;  // ���� ����
						DbgPrint("[INF : DRIVER] ���ΰ� ����� ���μ��� >>> handle ���ٰź� \n");
					}
					else {
						DbgPrint("[INF : DRIVER] ���ΰ� ����� ���μ��� >>> handle ������� \n");

					}

				}


			}
		}
	}
	return OB_PREOP_SUCCESS;
}



VOID RegisterCallbacks() {
	OB_CALLBACK_REGISTRATION callbackRegistration;
	OB_OPERATION_REGISTRATION operationRegistration;

	// �ݹ� ����ü �ʱ�ȭ
	RtlZeroMemory(&callbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
	RtlZeroMemory(&operationRegistration, sizeof(OB_OPERATION_REGISTRATION));

	UNICODE_STRING altitude;
	RtlInitUnicodeString(&altitude, L"370000"); // Altitude ���� �� ���� ����


	// �ݹ� ��Ͽ� �ʿ��� ����ü ����
	callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	callbackRegistration.OperationRegistrationCount = 1;
	callbackRegistration.Altitude = altitude;
	callbackRegistration.RegistrationContext = NULL;

	operationRegistration.ObjectType = PsProcessType; // ���μ��� Ÿ���� ������� ����
	operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	operationRegistration.PreOperation = PreOperationCallback; // ���� �ݹ� �Լ� ���
	operationRegistration.PostOperation = NULL; // ���� �ݹ��� �ʿ� ����

	callbackRegistration.OperationRegistration = &operationRegistration;

	// �ݹ� ���
	NTSTATUS status = ObRegisterCallbacks(&callbackRegistration, &g_CallbackHandle);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[ERROR : DRIVER] ���� ���� ��� �ݹ��Լ� ��� �� ���� �߻�. �����ڵ� : %08x\n", status);
	}
}



// =========================================================================================================== ioctl �κ� START

#define IOCTL_SEND_CDRIVER_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RECEIVE_STRING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {  // �ڵ��� ���� ����� ���ε� 
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	DbgPrint("[INF : DRIVER] ����̹� �ڵ��� ����\n");
	return STATUS_SUCCESS;
}



NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (controlCode == IOCTL_SEND_CDRIVER_NAME) {
		// ���� ���κ��� ���ڿ��� ����
		char* Cdriver = (char*)Irp->AssociatedIrp.SystemBuffer;
		DbgPrint("[INF : DRIVER] C����̺� NT Device Name : %s\n", Cdriver);
		WCHAR unicodeString[256];
		ULONG unicodeStringLength = 0;
		RtlMultiByteToUnicodeN(
			unicodeString,                 // ��� �����ڵ� ����
			sizeof(unicodeString),          // ��� ���� ũ�� (����Ʈ ����)
			&unicodeStringLength,           // ��ȯ�� �����ڵ� ���ڿ� ũ��
			Cdriver,                    // �Է� ANSI ���ڿ�
			(ULONG)strlen(Cdriver)              // �Է� ���ڿ� ����
		);

		WCHAR system32path[PATHNUM] = L"Windows\\System32\0";
		// ��ȯ�� �����ڵ� ���ڿ� ���� �� ���� ���� �߰�
		if (unicodeStringLength < 256) {
			int B = unicodeStringLength / sizeof(WCHAR);
			unicodeString[B] = L'\\';
			B++;
			int A = 0;
			while (A < PATHNUM) {
				unicodeString[B] = system32path[A++];
				B++;
			}
		}
		else {
			unicodeString[255] = L'\0';  // ���ڿ��� �� �� �ִ� ��� �������� �� ���� ���� �߰�
		}

		DbgPrint("[INF : DRIVER] C����̺� NT Device Name : %ls\n", unicodeString);


		//SetSystem32Path(unicodeString);
		//InitSystem32Path();
		BOOLEAN FLAG_ = TRUE;
		if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(BOOLEAN)) {
			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &FLAG_, sizeof(BOOLEAN));
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof(BOOLEAN);
		}
		else {
			Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;  // ���۰� ������ ����
		}
	}
	else if (controlCode == IOCTL_RECEIVE_STRING) {
		const char* message = NULL;
		
		size_t messageLen = strlen(message) + 1;

		LARGE_INTEGER interval;
		interval.QuadPart = -10000000;  // 1��(100������ ������ -10000000�� 1��)
		
		while (message == NULL)
			KeDelayExecutionThread(KernelMode, FALSE, &interval);   // �ش� Message�� �����ɶ����� ��޸���

		// ���� ����� ���۷� ���ڿ� ����
		if (messageLen <= stack->Parameters.DeviceIoControl.OutputBufferLength) {
			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, message, messageLen);
			Irp->IoStatus.Information = messageLen;
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		else {
			Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		}
	}
	else {
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
	}

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}



// =========================================================================================================== ioctl �κ� END

VOID UnregisterCallbacks(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	ObUnRegisterCallbacks(g_CallbackHandle);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	// �ɺ��� ��ũ ����

	if (pid != NULL) {
		UnregisterCallbacks(DriverObject);
	}


	NTSTATUS status = IoDeleteSymbolicLink(&symbolicLink);

	if (NT_SUCCESS(status)) {
		DbgPrint("[INF : DRIVER] �ɺ��� ��ũ ���� ����\n");
	}
	else {
		DbgPrint("[ERROR : DRIVER] �ɺ��� ��ũ ���� ����: 0x%X\n", status);
	}

	// ����̽� ��ü ����
	PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;
	while (DeviceObject != NULL) {
		PDEVICE_OBJECT NextDeviceObject = DeviceObject->NextDevice;
		IoDeleteDevice(DeviceObject);
		DeviceObject = NextDeviceObject;
	}

	DbgPrint("[INF : DRIVER] ����̹� ��ε� �Ϸ�\n");
}



NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	DbgPrint("[INF : DRIVER] ���� ���� ��� �ε�\n");
	DriverObject->DriverUnload = DriverUnload;
	InitializeWhiteListExternal();
	InitSystem32Path();
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\ExternalDevice");
	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ExternalDriver");
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status = IoCreateDevice(
		DriverObject,                // ����̹� ������Ʈ
		0,                           // ��ġ Ȯ�� ũ�� (����)
		&deviceName,                 // ��ġ �̸�
		FILE_DEVICE_UNKNOWN,         // ��ġ Ÿ��
		0,                           // Ư�� ����
		FALSE,                       // �ͽ�Ŭ��ú� ��� (FALSE = ���� ����)
		&DeviceObject                // ������ ��ġ ��ü ��ȯ
	);

	if (NT_SUCCESS(status)) {
		// �ɺ��� ��ũ ����
		status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
	}

	if (!NT_SUCCESS(status)) {
		DbgPrint("[ERROR : DRIVER] �ɺ��� ��ũ ���� ���� \n");
		return STATUS_UNSUCCESSFUL;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

	pid = Get_pid_from_name();   // Palshipping pid �������� 

	if (pid != NULL) {
		//DbgPrint("[INF : DRIVER] ����� �ĺ��Ϸ� PID =  %d\n", pid);
		RegisterCallbacks();
	}
	else {
		DbgPrint("[ERROR : DRIVER] ����尡 �߰ߵ��� �ʾҽ��ϴ�. ���� ���� ��� ����\n");
		return STATUS_UNSUCCESSFUL;
	}
	

	return STATUS_SUCCESS;
}


