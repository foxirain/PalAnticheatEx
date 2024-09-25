/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_ExternalAnticheat,
    0x5866c729,0x2d18,0x4232,0xae,0xdb,0xf6,0xac,0xcc,0x8c,0x10,0x10);
// {5866c729-2d18-4232-aedb-f6accc8c1010}
