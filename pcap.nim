import posix

when defined(macosx):
  const
    libName = "libpcap.dylib"
    ifName = "en0"
else:
  const
    libName = "libpcap.so"
    ifName = "eth0"

type
  pcap_t* {.importc: "pcap_t", header: "<pcap/pcap.h>".} = distinct pointer
  pcap_pkthdr* {.importc: "struct pcap_pkthdr", header: "<pcap/pcap.h>", final, pure.} = object
    ts*: Timeval
    caplen*: uint32
    len*: uint32
  ppcap_pkthdr* = ref pcap_pkthdr


proc pcap_open_live*(dev: cstring, snaplen: cint, promisc: cint, to_ms: cint, errbuf: pointer): pcap_t 
  {.cdecl, dynlib: libName, importc, discardable .}

proc pcap_create*(source: cstring, errbuf: pointer): pcap_t 
  {.cdecl, dynlib: libName, importc, discardable .}
proc pcap_activate*(pcap: pcap_t): cint 
  {.cdecl, dynlib: libName, importc, discardable .}

# pcap_findalldevs
# pcap_freealldevs
# pcap_lookupdev

proc pcap_open_offline*(fname: cstring, errbuf: pointer): pcap_t
  {.cdecl, dynlib: libName, importc, discardable .}

# pcap_fopen_offline
# pcap_open_dead

proc pcap_close*(pcap: pcap_t)
  {.cdecl, dynlib: libName, importc, discardable .}

proc pcap_set_snaplen*(pcap: pcap_t, snaplen: cint): cint 
  {.cdecl, dynlib: libName, importc, discardable .}
proc pcap_snapshot*(pcap: pcap_t): cint
  {.cdecl, dynlib: libName, importc, discardable .}

proc pcap_set_promisc*(pcap: pcap_t, promisc: cint): cint 
  {.cdecl, dynlib: libName, importc, discardable .}
proc pcap_set_rfmon*(pcap: pcap_t, rfmon: cint): cint 
  {.cdecl, dynlib: libName, importc, discardable .}
proc pcap_can_set_rfmon*(pcap: pcap_t): cint
  {.cdecl, dynlib: libName, importc, discardable .}

proc pcap_set_timeout*(pcap: pcap_t, to_ms: cint): cint 
  {.cdecl, dynlib: libName, importc, discardable .}

proc pcap_set_buffer_size*(pcap: pcap_t, buffer_size: cint): cint
  {.cdecl, dynlib: libName, importc, discardable .}

# pcap_set_tstamp_type
# pcap_list_tstamp_types
# pcap_free_tstamp_types
# pcap_tstamp_type_val_to_name
# pcap_tstamp_type_val_to_description
# pcap_tstamp_name_to_val
# pcap_datalink
# pcap_file
# pcap_is_swapped
# pcap_major_version
# pcap_minor_version

# pcap_dispatch
# pcap_loop

proc pcap_next*(pcap: pcap_t, ph: pointer): cstring
  {.cdecl, dynlib: libName, importc, discardable .}

# pcap_next_ex
# pcap_breakloop

proc pcap_setnonblock*(pcap: pcap_t, nonblock: cint, errbuf: pointer): cint
  {.cdecl, dynlib: libName, importc, discardable .}

proc pcap_getnonblock*(pcap: pcap_t, errbuf: pointer): cint
  {.cdecl, dynlib: libName, importc, discardable .}

proc pcap_get_selectable_fd*(pcap: pcap_t): cint
  {.cdecl, dynlib: libName, importc, discardable .}


proc valid*(pcap: pcap_t): bool =
  return (pcap.pointer != nil)

when isMainModule:
  var err = newString(256)
  err = "aaaa"
  # var p = pcap_open_live(ifName, 1500.cint, 1.cint, 5000.cint, addr(err))
  var p = pcap_create(ifName, addr(err))
  echo(repr(p), err)

  if valid(p):
    # pcap_set_buffer_size(p, 1500.cint)
    # p.pcap_set_nonblock(1, nil)
    p.pcap_set_timeout(1000.cint)
    pcap_activate(p)
    var ph: pcap_pkthdr
    var data = pcap_next(p, addr(ph))
    if data != nil:
      echo(ph.len, ", ", ph.caplen, " ", $ph.ts)
      var res: string = newString(ph.caplen)
      res.setLen(ph.caplen)
      copyMem(cast[pointer](res.cstring), data, ph.caplen)
    else:
      echo "Data is nil"
  else:
    echo "Could not open pcap"



