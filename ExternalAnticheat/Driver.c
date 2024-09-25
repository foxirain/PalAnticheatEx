#include <ntddk.h>

#define IOCTL_RECEIVE_STARTPAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RECEIVE_STARTEXTERNAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SEND_CDRIVER_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RECEIVE_STRING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

BOOLEAN PALSTART = FALSE;
BOOLEAN EXTERNALSTART = FALSE;

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

    if (controlCode == IOCTL_RECEIVE_STARTPAL) {
        // ���� ���κ��� ���ڿ��� ����



        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(BOOLEAN)) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &PALSTART, sizeof(BOOLEAN));  // ���� ���� ����
            Irp->IoStatus.Information = sizeof(BOOLEAN);
            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
        else {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;  // ���۰� ������ ����
        }


    }
    else if (controlCode == IOCTL_RECEIVE_STARTEXTERNAL) {
        // ���� ���κ��� ���ڿ��� ����



        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(BOOLEAN)) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &EXTERNALSTART, sizeof(BOOLEAN));  // ���� ���� ����
            Irp->IoStatus.Information = sizeof(BOOLEAN);
            Irp->IoStatus.Status = STATUS_SUCCESS;
        }
        else {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;  // ���۰� ������ ����
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
        DbgPrint("[INF : DRIVER] ���� ���� ��� ����̹� �ε� ����\n");
        EXTERNALSTART = TRUE;

        // ������ �ε带 ���� 5�� ��ٸ���
        LARGE_INTEGER interval;
        interval.QuadPart = -100000000;  // 5�� (100 ������ ������ 5��)

        KeDelayExecutionThread(KernelMode, FALSE, &interval);

    }
    else {
        DbgPrint("[ERROR : DRIVER] ���� ���� ��� ����̹� �ε� ����\n");
    }

}

VOID Pal_End(HANDLE ProcessId) {
    UNREFERENCED_PARAMETER(ProcessId);
    PALSTART = FALSE;
    NTSTATUS status = ZwUnloadDriver(&FocusMode_driver);
    if (NT_SUCCESS(status)) {
        DbgPrint("[INF : DRIVER] ���� ���� ��� ����̹� ��ε� ����\n");
        EXTERNALSTART = FALSE;
    }
    else {
        DbgPrint("[ERROR : DRIVER] ���� ���� ��� ����̹� ��ε� ����\n");

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
        // ���μ����� ������ �� ����
        UNICODE_STRING targetProcess;


        // ����� Shippig ���α׷� ��ġ   == IMPORTANT ==
        RtlInitUnicodeString(&targetProcess, L"\\??\\C:\\Program Files (x86)\\Steam\\steamapps\\common\\Palworld\\Pal\\Binaries\\Win64\\Palworld-Win64-Shipping.exe");


        if (CreateInfo->ImageFileName != NULL && RtlCompareUnicodeString(&targetProcess, CreateInfo->ImageFileName, TRUE) == 0) {

            if (targetPID) {
                DbgPrint("[ERROR : DRIVER] �ߺ��� ���μ��� \n");// �ߺ������μ���������
                //TerminateProcess(ProcessId);
                return;
            }
            targetPID = ProcessId;
            DbgPrint("[INF : DRIVER] ����� ���� ���μ��� �߰� PID = %d\n", ProcessId);
            Pal_Start(ProcessId);
        }
    }
    else {   // ���μ����� ����ɋ�
        if (ProcessId == targetPID) {
            DbgPrint("[INF:DRIVER] ����� ���μ��� ����\n");
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


    // ���μ��� ���� �ݹ��Լ� 
    status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ERROR : DRIVER] ���μ��� ���۽� �ݹ��Լ� ��� ���� \n");
        return status;
    }






    // ����̹� ���� �� ��Ÿ �ʱ�ȭ �۾�...
    return STATUS_SUCCESS;
}
