# Imports
from idc import BADADDR, INF_BASEADDR, SEARCH_DOWN, FUNCATTR_START, FUNCATTR_END
import idc
import idaapi
import idautils
import datetime
#find pattern and edit.

## 0x99 ignore patch.
##pattern - patch

patterns_patch = [
	["55 8B EC 83 EC 24 8B 45","\x00\x99\x00\x00\x00\xFF\x15\x18"],
	["55 8B EC 83 EC 24 8B 45","\x00\x99\x00\x00\x00\xFF\x15\x18"],
]

def PatchArr(dest, str):
  for i, c in enumerate(str):
	if ord(c) !=0x99:
		idc.PatchByte(dest+i, ord(c));
	
def pattern_scan(pattern):
	addr = idc.FindBinary(0, SEARCH_DOWN, pattern)
	if addr == BADADDR: return 0
	return addr
	
def find_func_pattern(pattern):
	addr = idc.FindBinary(0, SEARCH_DOWN, pattern)
	if addr == BADADDR: return 0

	try:
		return idaapi.get_func(addr).startEA
	except exception:
		return 0

for res in range(len(patterns_patch)):
		result = pattern_scan(patterns_patch[res][0])
		PatchArr(result,patterns_patch[res][1])
		#print hex(result)
		#print("index: %s | value: %s" % (res, patterns_patch[res]))
		#PatchArr(result,res[1])