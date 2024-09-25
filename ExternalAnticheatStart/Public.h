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

DEFINE_GUID (GUID_DEVINTERFACE_ExternalAnticheatStart,
    0x516e72fe,0xd2cf,0x4135,0x87,0xe9,0x26,0xcf,0x06,0x3c,0xc3,0x33);
// {516e72fe-d2cf-4135-87e9-26cf063cc333}
