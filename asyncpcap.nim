import asyncdispatch, asyncnet, rawsockets, net, os
import unsigned
import strutils
import pcap


type
  AsyncPcap* = ref object
    ifName: string
    pcap: pcap_t
    fd: AsyncFd
    snaplen: int

proc set_snaplen(ap: AsyncPcap, snaplen: int) =
  pcap_set_snaplen(ap.pcap, snaplen.cint)
  ap.snaplen = snaplen

proc newAsyncPcap(ifName: string, filter: string = nil): AsyncPcap =
  var err = newString(256)
  new result
  result.ifName = ifName
  result.pcap = pcap_create(ifName, addr(err))
  if valid(result.pcap):
    result.set_snaplen(1500)
    pcap_set_timeout(result.pcap, 1000.cint)
    pcap_activate(result.pcap)
    var fd = pcap_get_selectable_fd(result.pcap)
    if fd > 0:
      result.fd = fd.AsyncFd 
      register(result.fd)
    else:
      echo("PCAP: no selectable fd")
      result = nil
  
proc read_packet(ap: AsyncPcap): Future[string] =
  var retFuture = newFuture[string]("asyncpcap.read_packet")

  var readBuffer = newString(ap.snaplen)
  proc cb(fd: AsyncFd): bool =
    var ph: pcap_pkthdr
    result = true
    let data = pcap_next(ap.pcap, addr(ph))
    if data == nil:
      result = false # We still want this callback to be called
    else:
      readBuffer.setLen(ph.caplen)
      copyMem(addr readBuffer[0], data, ph.caplen)
      retFuture.complete(readBuffer)
  if not cb(ap.fd):
    addread(ap.fd, cb)

  return retFuture


when isMainModule:
  var ifName = "en0"

  proc runPcap() {.async.} =
    var apcap = newAsyncPcap("en0")
    while true:
      var s = await apcap.read_packet()
      echo("Read a packet, length:", s.len)

  asyncCheck runPcap()
  runForever()
  
