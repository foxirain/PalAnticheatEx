#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#define IOCTL_RECEIVE_STARTPAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RECEIVE_STARTEXTERNAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SEND_CDRIVER_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RECEIVE_STRING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_SIZE 2048

BOOL SendCdiverName(CHAR* cDriverName) {

	DWORD bytesReturned = NULL;
	HANDLE hDevice = CreateFileW(L"\\\\.\\ExternalDriver",
		GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("[ERROR : PalGuard] ���� ���� ��� Ž�� ���� Palworld�� �����մϴ�. \n");
		// Ŀ�� ����̹��� ���� ���� �ڵ带 ���� 
	}
	BOOL RECEIVED = FALSE;

	BOOL result = DeviceIoControl(hDevice,
		IOCTL_SEND_CDRIVER_NAME,
		cDriverName, strlen(cDriverName) + 1,
		&RECEIVED, sizeof(BOOLEAN),
		&bytesReturned,
		NULL);

	if (result) {
		if (RECEIVED) {
			printf("[INF : PalGuard] �ý��� ���� Ȯ�� �Ϸ�...\n");
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else {
		printf("[ERROR : PalGuard] �ý��� ���� Ȯ�� ���� �����ڵ� : 0x0001\n");
		return FALSE;
	}


	CloseHandle(hDevice);
	return FALSE;

}


BOOL WaitforExternalAnticheatSTART() {

	DWORD bytesReturned = NULL;
	HANDLE hDevice = CreateFileW(L"\\\\.\\ExternalStartDriver",
		GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("[ERROR : PalGuard] ���� ��� Ž�� ���� Palworld�� �����մϴ�. \n");
		// Ŀ�� ����̹��� ���� ���� �ڵ带 ���� 
	}
	BOOL EXTERNALANTICHEATSTART = FALSE;

	BOOL result = DeviceIoControl(hDevice,
		IOCTL_RECEIVE_STARTPAL,
		NULL, 0,
		&EXTERNALANTICHEATSTART, sizeof(EXTERNALANTICHEATSTART),
		&bytesReturned,
		NULL);

	if (result) {
		if (EXTERNALANTICHEATSTART) {
			printf("[INF : PalGuard] ���� ���ȸ�� ���� Ȯ��...\n");
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else {
		printf("[ERROR : PalGuard] �ý��� ���� Ȯ�� ���� �����ڵ� : 0x0001\n");
		return FALSE;
	}


	CloseHandle(hDevice);
	return FALSE;

}

BOOL WaitforPALSTART () {

	DWORD bytesReturned = NULL;
	HANDLE hDevice = CreateFileW(L"\\\\.\\ExternalStartDriver",
		GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("[ERROR : PalGuard] ���� ��� Ž�� ���� Palworld�� �����մϴ�. \n");
		// Ŀ�� ����̹��� ���� ���� �ڵ带 ���� 
	}
	BOOL PALSTART = FALSE;

	BOOL result = DeviceIoControl(hDevice,
		IOCTL_RECEIVE_STARTPAL,
		NULL, 0,
		&PALSTART, sizeof(PALSTART),
		&bytesReturned,
		NULL);

	if (result) {
		if (PALSTART) {
			printf("[INF : PalGuard] PAL ���� Ȯ��...\n");
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else {
		printf("[ERROR : PalGuard] �ý��� ���� Ȯ�� ���� �����ڵ� : 0x0001\n");
		return FALSE;
	}


	CloseHandle(hDevice);
	return FALSE;

}


int main(void) {
	CHAR szDriveBuf[MAX_SIZE] = { 0, };
	CHAR szFileSystem[MAX_SIZE] = { 0, };
	INT  nLen = GetLogicalDriveStringsA(sizeof(szDriveBuf), szDriveBuf);
	DWORD dwVolumnSerialNumber = 0;
	CHAR cDiverName[MAX_SIZE] = { 0, };

	printf(" ____               ___       ____                                  __     \n");
	printf("/\\  _`\\            /\\_ \\     /\\  _`\\                               /\\ \\    \n");
	printf("\\ \\ \\L\\ \\   __     \\//\\ \\    \\ \\ \\L\\_\\   __  __     __      _ __   \\_\\ \\   \n");
	printf(" \\ \\ ,__/ /'__`\\     \\ \\ \\    \\ \\ \\L_L  /\\ \\/\\ \\  /'__`\\   /\\`'__\\ /'_` \\  \n");
	printf("  \\ \\ \\/ /\\ \\L\\.\\_    \\_\\ \\_   \\ \\ \\/, \\\\ \\ \\_\\ \\/\\ \\L\\.\\_ \\ \\ \\/ /\\ \\L\\ \\ \n");
	printf("   \\ \\_\\ \\ \\__/.\\_\\   /\\____\\   \\ \\____/ \\ \\____/\\ \\__/.\\_\\ \\ \\_\\ \\ \\___,_\\ \n");
	printf("    \\/_/  \\/__/\\/_/   \\/____/    \\/___/   \\/___/  \\/__/\\/_/  \\/_/  \\/__,_ /\n");
	printf("\n"); 	printf("\n"); 	printf("\n"); 	printf("\n");




	CHAR szNtdeviceName[MAX_SIZE] = { 0, };
	for (int i = 0; i < nLen; i += 4) {
		CHAR szDriveNames[4] = { 0, };
		strncpy_s(szDriveNames, 4, &szDriveBuf[i], 2);
		bool bCheck = GetVolumeInformationA
		(
			&szDriveBuf[i],
			NULL,
			MAX_SIZE,
			&dwVolumnSerialNumber,
			NULL,
			NULL,
			szFileSystem,
			MAX_SIZE
		);

		if (bCheck == FALSE) {
			printf("[ERROR : PalGuard] ��� ã�� �� ����  %d\n ", GetLastError());
			dwVolumnSerialNumber = 0;
		}
		

		
		if (QueryDosDeviceA(szDriveNames, szNtdeviceName, MAX_SIZE)) {

			if (!strcmp(szDriveNames, "C:")) {
				printf("[INF : PalGuard] C����̺���  : %s DeviceName : %s\n", szDriveNames, szNtdeviceName);
				strcpy_s(cDiverName,szNtdeviceName);
			}
			
		}

	

	}

	if (!cDiverName) {
		printf("[ERROR : PalGuard] C ����̺� ��� ã�� ����, PalGuard�� �����մϴ�.\n");
		return 0;
	}

	
	

	while (!WaitforPALSTART()) {
		printf("[INF : PalGuard] Pal ������ ��ٸ��� ��...\n");
		Sleep(5000);
	}
	printf("[INF:PalGuard] Pal ���� Ȯ��.\n");

	while (!WaitforExternalAnticheatSTART()) {
		printf("[INF : PalGuard] ���� ���� ��� ������ ��ٸ��� ��...\n");
		Sleep(5000);
	}
	printf("[INF:PalGuard] ���� ���� ��� ���� Ȯ��.\n");

	while (!SendCdiverName(cDiverName)) {
		printf("[INF : PalGuard] �ý��� ���� Ȯ��  ��ٸ��� ��...\n");
		Sleep(5000);
	}

	printf("[INF : PalGuard] ��ƼġƮ�� Ȱ��ȭ �Ǿ� �ֽ��ϴ�...\n");
	while (1) {
		Sleep(5000);
	}

	





	return 0;
}