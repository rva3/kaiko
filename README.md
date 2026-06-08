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
processes 75.5k instructions (411 fns, 15.1k blocks) in 90ms (ryzen 7 7435hs)

#### compiler optimization
- Cargo.toml: `opt-level = 3` + `lto = true` (or = "thin" for a bit larger binary)
- PGO + BOLT:
```
# build PGO bin
cargo pgo instrument build -- --features cli,no_tracers

# run to collect PGO profiles
./target/x86_64-unknown-linux-gnu/release/cli ...

# build BOLT bin (requires BOLT installed)
cargo pgo bolt build --with-pgo -- --features cli,no_tracers

# run to collect BOLT profiles
./target/x86_64-unknown-linux-gnu/release/cli-bolt-instrumented ...

# build final bin
cargo pgo bolt optimize --with-pgo -- --features cli,no_tracers

# target bin
file ./target/x86_64-unknown-linux-gnu/release/cli-bolt-optimized
```

note that PGO and BOLT need rebuild after every minor change for best results.

applying PGO + BOLT gives ~75ms execution time on the same hardware and binary.

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

## FAQ
- \>too many logs
- enable `no_tracers` feature.
- \>bad code quality
- i haven't seen ARM analysis with a good code yet.
- \>there's invalid instruction at the end of the function
- DCE and noreturn analysis are somewhere at the end of TODO.

## license
[AGPLv3](./LICENSE)

please note static linking into proprietary binary is a violation of the license.
