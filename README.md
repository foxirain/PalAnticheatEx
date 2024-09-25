# PalAnticheatEx
화이트햇 스쿨 2기 고도화 및 개인 프로젝트 


일단, 핵에 대한 전혀 불법적인 행동을 하지 않았으며 게임회사에 대한 어떤 불법적인 행동 혹은 윤리적으로 어긋난 행동을 하지 않았음을 선업합니다.

개요 : 게임 핵을 막기 위한 커널 드라이버 및 프로그램 제작
사용법 
1. ExternalAnticheatStart sln 파일에서 127 번째 줄을 자신의 펠월드 Shipping 위치로 설정해 줍니다. ( 기본 위치 : 스팀 디렉토리 아래 )
2. 둘다 컴파일을 진행하여 줍니다.
3. 시스템에서 Testing mod를 켜줍니다. ( 서명되지 않은 드라이버를 올려야 하기 때문 )
4. 관리자 권한으로 CMD를 켜줍니다.
5. sc create ExternalDriver type=kernel binPath="( ExternalAnticheat.sys 의 주소 )"
6. sc create ExternalStartDriver type=kernel binPath="( ExternalAnticheatStart.sys 의 주소 )"
7. sc start ExternalStartDriver
8. PalGuard.exe를 실행해 줍니다.

이제 부터 기본적인 설정은 끝났고 앞으로 Palworld shipping.exe 가 실행 될때마다 자동적으로 ExternalAnticheat 드라이버가 올라갑니다.
만약 `sc start ExternalStartDriver`  명령어를 일일히 컴퓨터가 켜질때 마다 치고 싶지 않다면, 즉 컴퓨터가 켜질때 마다 ExternalAnticheatStart 를 자동으로 로드 시키고 싶다면
sc create 명령어를 사용할때 뒤에 `start= auto` 옵션을 추가하면 됩니다.

구현 내용
IOCTL을 통한 커널<->프로세스 통신
커널 드라이버 제작
커널 드라이버 상 IRP 컨트롤
커널 드라이버 상 후킹 및 콜백 함수 제작

구현 범위
INTERNAL 핵 BLOCK  ( DLL Injection )
EXTERNAL 핵 BLOCK  ( WPM , RPM , HANDLE 접근 )

상세 내용
ExternalAnticheat -  메인 보안 모듈
ExternalAnticheatStart  - 메인 보안 모듈를 올리기 위한 용도로 안티디버깅 및 악성 커널 드라이버의 로드를 차단하기 위한 용도로 추후 수정 가능
PalGuard - 사용자와의 인터페이스 ( 커널 드라이브 상에서 어떻게 작동되는지 사용자가 알 수 없으니 사용자와의 인터페이스를 제작하고 자 함)

본 안티치트는 상업용이 아닙니다.

제작인 : 팀 WhiteGang 하태구
