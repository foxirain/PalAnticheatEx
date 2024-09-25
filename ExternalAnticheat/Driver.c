#include <ntddk.h>

#define IOCTL_RECEIVE_STARTPAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RECEIVE_STARTEXTERNAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SEND_CDRIVER_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RECEIVE_STRING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

BOOLEAN PALSTART = FALSE;
BOOLEAN EXTERNALSTART = FALSE;

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

    if (controlCode == IOCTL_RECEIVE_STARTPAL) {
        // 유저 모드로부터 문자열을 받음



        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(BOOLEAN)) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &PALSTART, sizeof(BOOLEAN));  // 유저 모드로 전송
            Irp->IoStatus.Information = sizeof(BOOLEAN);
            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
        else {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;  // 버퍼가 작으면 오류
        }


    }
    else if (controlCode == IOCTL_RECEIVE_STARTEXTERNAL) {
        // 유저 모드로부터 문자열을 받음



        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(BOOLEAN)) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &EXTERNALSTART, sizeof(BOOLEAN));  // 유저 모드로 전송
            Irp->IoStatus.Information = sizeof(BOOLEAN);
            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
        else {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;  // 버퍼가 작으면 오류
        }

 
    }
    else {
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}



UNICODE_STRING FocusMode_driver = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\ExternalDriver");

VOID Pal_Start(HANDLE ProcessId) {
    UNREFERENCED_PARAMETER(ProcessId);
    PALSTART = TRUE;



    NTSTATUS status = ZwLoadDriver(&FocusMode_driver);
    if (NT_SUCCESS(status)) {
        DbgPrint("[INF : DRIVER] 메인 보안 모듈 드라이버 로드 성공\n");
        EXTERNALSTART = TRUE;

        // 완전한 로드를 위해 5초 기다리기
        LARGE_INTEGER interval;
        interval.QuadPart = -100000000;  // 5초 (100 나노초 단위로 5초)

        KeDelayExecutionThread(KernelMode, FALSE, &interval);

    }
    else {
        DbgPrint("[ERROR : DRIVER] 메인 보안 모듈 드라이버 로드 실패\n");
    }

}

VOID Pal_End(HANDLE ProcessId) {
    UNREFERENCED_PARAMETER(ProcessId);
    PALSTART = FALSE;
    NTSTATUS status = ZwUnloadDriver(&FocusMode_driver);
    if (NT_SUCCESS(status)) {
        DbgPrint("[INF : DRIVER] 메인 보안 모듈 드라이버 언로드 성공\n");
        EXTERNALSTART = FALSE;
    }
    else {
        DbgPrint("[ERROR : DRIVER] 메인 보안 모듈 드라이버 언로드 실패\n");

    }


}



HANDLE targetPID = NULL;
VOID CreateProcessNotifyEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo != NULL) {
        // 프로세스가 생성될 때 실행
        UNICODE_STRING targetProcess;


        // 펠월드 Shippig 프로그램 위치   == IMPORTANT ==
        RtlInitUnicodeString(&targetProcess, L"\\??\\C:\\Program Files (x86)\\Steam\\steamapps\\common\\Palworld\\Pal\\Binaries\\Win64\\Palworld-Win64-Shipping.exe");


        if (CreateInfo->ImageFileName != NULL && RtlCompareUnicodeString(&targetProcess, CreateInfo->ImageFileName, TRUE) == 0) {

            if (targetPID) {
                DbgPrint("[ERROR : DRIVER] 중복된 프로세스 \n");// 중복　프로세스　방지
                //TerminateProcess(ProcessId);
                return;
            }
            targetPID = ProcessId;
            DbgPrint("[INF : DRIVER] 펠월드 게임 프로세스 발견 PID = %d\n", ProcessId);
            Pal_Start(ProcessId);
        }
    }
    else {   // 프로세스가 종료될떄
        if (ProcessId == targetPID) {
            DbgPrint("[INF:DRIVER] 펠월드 프로세스 종료\n");
            Pal_End(ProcessId);
            targetPID = NULL;
        }


    }
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\ExternalStartDevice");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ExternalStartDriver");

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


    // 프로세스 시작 콜백함수 
    status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ERROR : DRIVER] 프로세스 시작시 콜백함수 등록 실패 \n");
        return status;
    }






    // 드라이버 생성 및 기타 초기화 작업...
    return STATUS_SUCCESS;
}
