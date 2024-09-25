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

	status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);  // 여기서 일부로 버퍼 크기를 틀리면 bufferSize 에 필요한 크기가 담겨서 온다.
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'MDMP');   // 해당 bufferSize 만큼 할당
		if (buffer == NULL) {
			DbgPrint( "[ERROR : DRIVER] buffer 할당 오류 \n");
			return pCurrent;
		}
		else {
			status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);   // 진짜 가져오기
			if (!NT_SUCCESS(status)) {
				DbgPrint("[ERROR : DRIVER] 펠월드 프로세스가 존재하지 않습니다. \n");
				ExFreePoolWithTag(buffer, 'MDMP');
				return pCurrent;
			}
		}
	}


	DbgPrint("[INF : DRIVER] 펠월드 프로세스 확인 완료 \n");



	pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
	while (pCurrent) {
		if (pCurrent->ImageName.Buffer != NULL) {
			if (RtlCompareUnicodeString(&(pCurrent->ImageName), &processName, TRUE) == 0) {
				DbgPrint("[INF : DRIVER] 펠월드 PID = %d \n ", pCurrent->ProcessId);
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

	DbgPrint("[INF : DRIVER] C드라이버 동적 설정 완료 : %ws \n", cDriverName);
	DbgPrint("[INF : DRIVER] 다음으로 설정 : %wZ \n ", &SYSTEM32_PATH);

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

#define WHITELIST_SIZE 6 // 화이트리스트 크기 정의
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

	// 파일 이름 부분의 시작 주소를 구함
	PWCHAR fileNameStart = &processName->Buffer[i];

	// 파일 이름을 UNICODE_STRING으로 만듦
	UNICODE_STRING fileName;
	RtlInitUnicodeString(&fileName, fileNameStart);

	// 추출된 파일 이름 출력
	DbgPrint("추출된 파일 이름: %wZ\n", &fileName);

	// 화이트리스트와 비교
	for (int t = 0; t < WHITELIST_SIZE; t++) {
		if (RtlEqualUnicodeString(&whiteListE[t], &fileName, TRUE)) {
			return TRUE; // 화이트리스트에 있는 경우
		}
	}

	return FALSE; // 화이트리스트에 없는 경우
}




OB_PREOP_CALLBACK_STATUS PreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {

	UNREFERENCED_PARAMETER(RegistrationContext);
	// 접근하려는 대상이 프로세스인지 확인
	if (OperationInformation->ObjectType == *PsProcessType) {
		PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;

		// 특정 프로세스에 대한 핸들 접근을 차단 -> FindProcessByName 함수로 가져온 pid 로
		if (PsGetProcessId(targetProcess) == pid) {

			PEPROCESS currentProcess = PsGetCurrentProcess();  // 핸들에 접근한 프로세스
			PUNICODE_STRING currentProcessName = NULL;

			SeLocateProcessImageName(currentProcess, &currentProcessName);



			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {   // 이게 문제일수도

				DbgPrint("[INF : DRIVER] 펠월드 핸들 접근 :  %wZ\n", currentProcessName); // 프로세스 이름 출력
				if (currentProcess == targetProcess || IsInWhiteList(currentProcessName)) {
					DbgPrint("[INF : DRIVER] 신뢰성있는 사용자 프로세스 >>> handle 접근허용\n");
					return OB_PREOP_SUCCESS;
				}

				if (IsInSystem32Directory(currentProcessName)) {
					DbgPrint("[INF : DRIVER] 시스템 프로세스 >>> handle 접근허용\n");
					return OB_PREOP_SUCCESS;

				}
				else {  // 사용자 프로세스 인데 화이트리스트에 없음

					ULONG desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
					DbgPrint("[INF : DRIVER] 비인가 사용자 프로세스 요청한 권한 : 0x%X\n", desiredAccess);
					if ((desiredAccess & PROCESS_VM_WRITE) ||
						(desiredAccess & PROCESS_VM_OPERATION) ||
						(desiredAccess & PROCESS_DUP_HANDLE)) {

						// 쓰기 권한 접근 차단
						OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;  // 접근 차단
						DbgPrint("[INF : DRIVER] 비인가 사용자 프로세스 >>> handle 접근거부 \n");
					}
					else {
						DbgPrint("[INF : DRIVER] 비인가 사용자 프로세스 >>> handle 접근허용 \n");

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

	// 콜백 구조체 초기화
	RtlZeroMemory(&callbackRegistration, sizeof(OB_CALLBACK_REGISTRATION));
	RtlZeroMemory(&operationRegistration, sizeof(OB_OPERATION_REGISTRATION));

	UNICODE_STRING altitude;
	RtlInitUnicodeString(&altitude, L"370000"); // Altitude 값을 더 높게 설정


	// 콜백 등록에 필요한 구조체 세팅
	callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	callbackRegistration.OperationRegistrationCount = 1;
	callbackRegistration.Altitude = altitude;
	callbackRegistration.RegistrationContext = NULL;

	operationRegistration.ObjectType = PsProcessType; // 프로세스 타입을 대상으로 설정
	operationRegistration.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	operationRegistration.PreOperation = PreOperationCallback; // 사전 콜백 함수 등록
	operationRegistration.PostOperation = NULL; // 사후 콜백은 필요 없음

	callbackRegistration.OperationRegistration = &operationRegistration;

	// 콜백 등록
	NTSTATUS status = ObRegisterCallbacks(&callbackRegistration, &g_CallbackHandle);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[ERROR : DRIVER] 메인 보안 모듈 콜백함수 등록 중 문제 발생. 에러코드 : %08x\n", status);
	}
}



// =========================================================================================================== ioctl 부분 START

#define IOCTL_SEND_CDRIVER_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RECEIVE_STRING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {  // 핸들을 열때 생기는 거인듯 
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	DbgPrint("[INF : DRIVER] 드라이버 핸들이 열림\n");
	return STATUS_SUCCESS;
}



NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (controlCode == IOCTL_SEND_CDRIVER_NAME) {
		// 유저 모드로부터 문자열을 받음
		char* Cdriver = (char*)Irp->AssociatedIrp.SystemBuffer;
		DbgPrint("[INF : DRIVER] C드라이브 NT Device Name : %s\n", Cdriver);
		WCHAR unicodeString[256];
		ULONG unicodeStringLength = 0;
		RtlMultiByteToUnicodeN(
			unicodeString,                 // 출력 유니코드 버퍼
			sizeof(unicodeString),          // 출력 버퍼 크기 (바이트 단위)
			&unicodeStringLength,           // 변환된 유니코드 문자열 크기
			Cdriver,                    // 입력 ANSI 문자열
			(ULONG)strlen(Cdriver)              // 입력 문자열 길이
		);

		WCHAR system32path[PATHNUM] = L"Windows\\System32\0";
		// 변환된 유니코드 문자열 끝에 널 종료 문자 추가
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
			unicodeString[255] = L'\0';  // 문자열이 꽉 차 있는 경우 마지막에 널 종료 문자 추가
		}

		DbgPrint("[INF : DRIVER] C드라이브 NT Device Name : %ls\n", unicodeString);


		//SetSystem32Path(unicodeString);
		//InitSystem32Path();
		BOOLEAN FLAG_ = TRUE;
		if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(BOOLEAN)) {
			RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &FLAG_, sizeof(BOOLEAN));
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof(BOOLEAN);
		}
		else {
			Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;  // 버퍼가 작으면 오류
		}
	}
	else if (controlCode == IOCTL_RECEIVE_STRING) {
		const char* message = NULL;
		
		size_t messageLen = strlen(message) + 1;

		LARGE_INTEGER interval;
		interval.QuadPart = -10000000;  // 1초(100나노초 단위로 -10000000이 1초)
		
		while (message == NULL)
			KeDelayExecutionThread(KernelMode, FALSE, &interval);   // 해당 Message가 생성될때까지 기달리기

		// 유저 모드의 버퍼로 문자열 복사
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



// =========================================================================================================== ioctl 부분 END

VOID UnregisterCallbacks(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	ObUnRegisterCallbacks(g_CallbackHandle);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	// 심볼릭 링크 삭제

	if (pid != NULL) {
		UnregisterCallbacks(DriverObject);
	}


	NTSTATUS status = IoDeleteSymbolicLink(&symbolicLink);

	if (NT_SUCCESS(status)) {
		DbgPrint("[INF : DRIVER] 심볼릭 링크 삭제 성공\n");
	}
	else {
		DbgPrint("[ERROR : DRIVER] 심볼릭 링크 삭제 실패: 0x%X\n", status);
	}

	// 디바이스 객체 삭제
	PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;
	while (DeviceObject != NULL) {
		PDEVICE_OBJECT NextDeviceObject = DeviceObject->NextDevice;
		IoDeleteDevice(DeviceObject);
		DeviceObject = NextDeviceObject;
	}

	DbgPrint("[INF : DRIVER] 드라이버 언로드 완료\n");
}



NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	DbgPrint("[INF : DRIVER] 메인 보안 모듈 로드\n");
	DriverObject->DriverUnload = DriverUnload;
	InitializeWhiteListExternal();
	InitSystem32Path();
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\ExternalDevice");
	UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ExternalDriver");
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status = IoCreateDevice(
		DriverObject,                // 드라이버 오브젝트
		0,                           // 장치 확장 크기 (없음)
		&deviceName,                 // 장치 이름
		FILE_DEVICE_UNKNOWN,         // 장치 타입
		0,                           // 특성 없음
		FALSE,                       // 익스클루시브 사용 (FALSE = 공유 가능)
		&DeviceObject                // 생성된 장치 객체 반환
	);

	if (NT_SUCCESS(status)) {
		// 심볼릭 링크 생성
		status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
	}

	if (!NT_SUCCESS(status)) {
		DbgPrint("[ERROR : DRIVER] 심볼릭 링크 생성 에러 \n");
		return STATUS_UNSUCCESSFUL;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

	pid = Get_pid_from_name();   // Palshipping pid 가져오기 

	if (pid != NULL) {
		//DbgPrint("[INF : DRIVER] 펠월드 식별완료 PID =  %d\n", pid);
		RegisterCallbacks();
	}
	else {
		DbgPrint("[ERROR : DRIVER] 펠월드가 발견되지 않았습니다. 메인 보안 모듈 종료\n");
		return STATUS_UNSUCCESSFUL;
	}
	

	return STATUS_SUCCESS;
}


