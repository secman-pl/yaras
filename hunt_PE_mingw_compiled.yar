rule hunt_PE_mingw_compiled {
    meta:

        OneHundredDaysOfYARA    = "2/100"
        author                  = "Bartek Jerzman"
        description             = "Hunting for PE files compiled with MingGW"
        vt_search               = "content:\"GCC: (MinGW.org\" and tag:peexe"

    strings:

        $mingw = "GCC: (MinGW.org" fullword ascii
   
   condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        $mingw
}
