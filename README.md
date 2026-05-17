# kaiko
`kaiko` is an architecture-aware, automated binary analyzer designed for the ARM/Thumb ISAs. 

## features
- recursive disassembly
- fast?
- small (~100kb in release mode for x86, around 25% of the size is yaxpeax-arm)
- lifting up to basic blocks and functions
- literal and register state tracking

### recursive disassembly
`kaiko` follows the direct branches in the assembly to build the initial instruction pool. then it
computes the register state and resolves the indirect jumps, feeding back new data until no new
instructions are found.

### fast?
faster than the Ghidra and not-so-much-faster than the IDA Pro. mostly due to less features.

### small
can be embedded into a rust application without FFI for IDA or Ghidra. with `opt-level = "z"`, fat
LTO and `codegen-units = 1` the size can be reduced to the 70kb (x86).

### lifting up to basic blocks and functions
the API exposes basic blocks and functions as high-level objects. original instructions can also be
retrieved using the `.code()` method.

### literal and register state tracking
while there's no SSA-like algorithm, but rather a simple array for 16 registers, `kaiko` is able to
resolve register state in most cases.

literals are not exposed to the user; rather, they are used for string lookups.

### why
i haven't found any good ARM binary analyzer that doesn't use code heuristics or pattern matching.
also because i can.

### perf
obviously, this is (notably) slower than byte comparison or code heuristics, but instead we're
getting much more reliable output.

## usage
`cargo r --release --features cli -- --help` for cli test

`cargo add --git https://github.com/rva3/kaiko` for lib

## license
[AGPLv3](./LICENSE)

please note static linking into proprietary binary is a violation of the license.
