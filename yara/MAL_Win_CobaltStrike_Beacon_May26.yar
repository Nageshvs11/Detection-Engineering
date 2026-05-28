rule MAL_Win_CobaltStrike_Beacon_May26 {
    meta:
        description     = "Detects Cobalt Strike beacon payload via XOR-encoded configuration block markers, default Malleable C2 named pipe strings, and characteristic beacon error messages"
        author          = "Detection KB"
        date            = "2026-05-27"
        reference       = "https://www.elastic.co/security-labs/detecting-cobalt-strike-with-memory-signatures"
        reference2      = "https://research.nccgroup.com/2020/06/15/striking-back-at-retired-cobalt-strike/"
        reference3      = "https://blog.cobaltstrike.com/2020/06/25/cobalt-strike-4-0-review/"
        hash_sample     = "see: https://bazaar.abuse.ch/browse/tag/cobalt-strike/"
        // Verified XOR derivations:
        //   Config block record: [type:uint16be][length:uint16be][value:N]
        //   Setting 1 BeaconType: 00 01 | 00 02 | 00 0X
        //   Setting 2 Port:       00 02 | 00 02 | PP PP
        //   Setting 3 SleepTime:  00 03 | 00 04 | ...
        //   XOR key 0x69 → bytes above XOR'd produce the $cfg_xor69 pattern
        //   XOR key 0x2E → same fields XOR'd produce $cfg_xor2e

    strings:
        // GROUP A: XOR-encoded configuration block markers
        //   CS3.x / CS4.x — key 0x69
        //   Decodes to: BeaconType(type=1,len=2,val=HTTP/HTTPS/SMB)
        //               Port(type=2,len=2,val=any)
        //               SleepTime header(type=3,len=4)
        $cfg_xor69 = { 69 68 69 6B 69 6? 69 6B 69 6B ?? ?? 69 6A 69 6D }

        //   CS4.x alternate — key 0x2E (seen in cracked/redistributed builds)
        $cfg_xor2e = { 2E 2F 2E 2C 2E 2? 2E 2C 2E 2C ?? ?? 2E 2D 2E 2A }

        //   Plaintext / in-memory decoded config (post-unpack or memory scan)
        $cfg_plain = { 00 01 00 02 00 0? 00 02 00 02 ?? ?? 00 03 00 04 }

        // GROUP B: Default Malleable C2 named pipe patterns
        //   Operators frequently leave these at CS defaults — high signal
        $pipe_msse       = "\\pipe\\MSSE-" ascii wide
        $pipe_msagent    = "\\pipe\\msagent_" ascii wide
        $pipe_postex_ssh = "\\pipe\\postex_ssh_" ascii wide
        $pipe_postex     = "\\pipe\\postex_" ascii wide
        $pipe_status     = "\\pipe\\status_" ascii wide

        // GROUP C: Characteristic strings embedded in the beacon DLL
        //   These error/debug messages are unique to CS and absent in legitimate software
        $str_x64_inject  = "%d is an x64 process (can't inject x86 content)" ascii
        $str_impersonate = "Failed to impersonate logged on user %d" ascii
        $str_beacon_dll  = "beacon.dll" ascii
        $str_reflective  = "ReflectiveDll" ascii

    condition:
        // Short-circuit: cheap PE header check before any string scanning
        uint16(0) == 0x5A4D and
        filesize < 10000000 and
        (
            // A single config XOR marker is CS-specific — sufficient alone
            1 of ($cfg_*) or
            // Two or more default pipe names confirms operator using CS default profile
            2 of ($pipe_*) or
            // One named pipe + one characteristic string = corroborating evidence
            ( any of ($pipe_*) and any of ($str_*) )
        )
}
