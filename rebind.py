#!/usr/bin/env python3

import argparse
import lief

def to_binding(binding):
  if args.binding is None:
    return None
  elif binding == 'global':
    return lief.ELF.SYMBOL_BINDINGS.GLOBAL
  elif binding == 'weak':
    return lief.ELF.SYMBOL_BINDINGS.WEAK
  else:
    print("Error: Unsupported symbol binding:", binding)
    exit(1)

def to_visibility(visibility):
  if visibility is None:
    return None
  elif visibility == 'default':
    return lief.ELF.SYMBOL_VISIBILITY.DEFAULT
  elif visibility == 'hidden':
    return lief.ELF.SYMBOL_VISIBILITY.HIDDEN
  else:
    print("Error: Unsupported symbol visibility:", visibility)
    exit(1)

parser = argparse.ArgumentParser()
parser.add_argument('file', metavar='FILE', help='the file')
parser.add_argument('symbols', metavar='SYMBOLS', nargs='+', help='the symbols to modify')

parser.add_argument('-b', dest='binding', metavar='BIND', type=str.lower, help='change the symbol binding to BIND')
parser.add_argument('-v', dest='visibility', metavar='VIS', type=str.lower, help='change the symbol visibility to VIS')
parser.add_argument('--prefix', dest='prefix', metavar='PREFIX', help='Duplicate symbol and add this prefix')
parser.add_argument('--affix', dest='affix', metavar='AFFIX', help='Duplicate symbol and add this affix')
parser.add_argument('-o', dest='out', metavar='OUTFILE', help='set out file (default: overwrite FILE)')
parser.add_argument('-V', dest='verbose', action='store_true', help='verbose')

args = parser.parse_args()

file = lief.parse(args.file)

binding = to_binding(args.binding)
visibility = to_visibility(args.visibility)
duplicate = args.prefix is not None or args.affix is not None

for sym in args.symbols:
  if args.verbose:
    print("- Processing symbol:", sym)

  symbol = file.get_symbol(sym)

  if duplicate:
    symbol = file.add_static_symbol(symbol)
    if args.prefix is not None:
      symbol.name = args.prefix + symbol.name
    if args.affix is not None:
      symbol.name = symbol.name + args.affix

  if binding is not None and binding != symbol.binding:
    was_local = symbol.binding == lief.ELF.SYMBOL_BINDINGS.LOCAL

    if args.verbose:
      print(f"  - Changing binding from {symbol.binding.name} to {binding.name}")
      if was_local:
        print("    - Adding to dynamic symbol table")
    
    symbol.binding = binding

    if was_local or duplicate:
      file.add_dynamic_symbol(symbol)

  if visibility is not None and visibility != symbol.visibility:
    if args.verbose:
      print(f"  - Changing visibility from {symbol.visibility.name} to {visibility.name}")

    symbol.visibility = visibility

if args.verbose:
  if args.out is None:
    print("- Overwriting", args.file)
  else:
    print("- Writing to file:", args.out)

file.write(args.out if args.out is not None else args.file)
