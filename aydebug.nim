# Copyright (c) 2015 Andrew Yourtchenko. MIT license

import strutils

# Some debug/analysis functions.

proc hexdump*(data: string): string = ## return the hex dump of the string as a string
  var acc_x = ""
  var acc_c = ""
  result = ""
  for i in 0 .. data.len-1:
    var c = data[i]
    if i mod 16 == 0:
      acc_x.add(i.toHex(4) & ": ")
    acc_x.add(c.int.toHex(2) & " ")
    if c.int < 32 or c.int >= 128:
      acc_c.add(".")
    else:
      acc_c.add(c)
    if i mod 16 == 15:
      result.add(acc_x & acc_c & "\n")
      acc_x = ""
      acc_c = ""
  while acc_x.len < 16*3+5:
    acc_x.add("   ")
  result.add(acc_x & acc_c & "\n")


if isMainModule:
  var str1 = "0123456789abcdef"
  echo("16 chars:\n", hexdump(str1))
  str1 = "0123456789\27abcdef"
  echo("17 chars, with an unprintable:\n", hexdump(str1))
