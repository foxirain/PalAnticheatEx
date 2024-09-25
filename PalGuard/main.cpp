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
		printf("[ERROR : PalGuard] 메인 보안 모듈 탐색 실패 Palworld를 종료합니다. \n");
		// 커널 드라이버로 게임 종료 코드를 보냄 
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
			printf("[INF : PalGuard] 시스템 정보 확인 완료...\n");
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else {
		printf("[ERROR : PalGuard] 시스템 정보 확인 실패 에러코드 : 0x0001\n");
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
		printf("[ERROR : PalGuard] 보안 모듈 탐색 실패 Palworld를 종료합니다. \n");
		// 커널 드라이버로 게임 종료 코드를 보냄 
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
			printf("[INF : PalGuard] 메인 보안모듈 시작 확인...\n");
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else {
		printf("[ERROR : PalGuard] 시스템 정보 확인 실패 에러코드 : 0x0001\n");
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
		printf("[ERROR : PalGuard] 보안 모듈 탐색 실패 Palworld를 종료합니다. \n");
		// 커널 드라이버로 게임 종료 코드를 보냄 
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
			printf("[INF : PalGuard] PAL 시작 확인...\n");
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else {
		printf("[ERROR : PalGuard] 시스템 정보 확인 실패 에러코드 : 0x0001\n");
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
			printf("[ERROR : PalGuard] 뷸륨 찾기 중 오류  %d\n ", GetLastError());
			dwVolumnSerialNumber = 0;
		}
		

		
		if (QueryDosDeviceA(szDriveNames, szNtdeviceName, MAX_SIZE)) {

			if (!strcmp(szDriveNames, "C:")) {
				printf("[INF : PalGuard] C드라이브의  : %s DeviceName : %s\n", szDriveNames, szNtdeviceName);
				strcpy_s(cDiverName,szNtdeviceName);
			}
			
		}

	

	}

	if (!cDiverName) {
		printf("[ERROR : PalGuard] C 드라이브 뷸륨 찾기 실패, PalGuard를 종료합니다.\n");
		return 0;
	}

	
	

	while (!WaitforPALSTART()) {
		printf("[INF : PalGuard] Pal 시작을 기다리는 중...\n");
		Sleep(5000);
	}
	printf("[INF:PalGuard] Pal 시작 확인.\n");

	while (!WaitforExternalAnticheatSTART()) {
		printf("[INF : PalGuard] 메인 보안 모듈 시작을 기다리는 중...\n");
		Sleep(5000);
	}
	printf("[INF:PalGuard] 메인 보안 모듈 시작 확인.\n");

	while (!SendCdiverName(cDiverName)) {
		printf("[INF : PalGuard] 시스템 정보 확인  기다리는 중...\n");
		Sleep(5000);
	}

	printf("[INF : PalGuard] 안티치트가 활성화 되어 있습니다...\n");
	while (1) {
		Sleep(5000);
	}

	





	return 0;
}