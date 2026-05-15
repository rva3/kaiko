kaiko is ARM binary analyzer designed for architecture-aware automated binary analysis.

## features
- recursive analysis with basic blocks and functions
- self-tests
- fast?
- small?

## usage
`cargo r --release --features cli -- --help` for cli test

`cargo add --git https://github.com/rva3/kaiko` for lib

## this is my brain dump before i write proper readme
for usage refer to [lib.rs](./src/lib.rs), it should give brief explanation on how API
looks like.

some planned features like register tracking are not very polished yet.

### why
i haven't found any good ARM binary analyzer so far. most tools either use pattern matching or
code heuristics, even worse if it's raw instruction matching without any validation.

let's imagine you're searching for some string in the binary and then want to get
function. sure, searching string and instruction which holds reference is pretty easy, but what's
next? how would you determine prologue? yes, there are few heuristics like `PUSH {..., LR}`, but
they don't work for leaf functions. finding prologue is much harder than the epilogue.

it becomes even more fun when we're talking about ARM/Thumb mixed binaries, because you never
know if it's ARM or Thumb `LDR`, `ADR` or whatever. this requires 2 runs (at worst) to detect
the instruction set.

but the real problem is control flow graph. if you want to get the value in the register then
you should know block boundary. sure, you can walk until instruction hits the same register, but
how do you know it's not the other block?

### so?
besides the issues above, QoL things like literal tracking, function XREFs, register state
tracking etc etc are very hard to implement without proper analysis.

that said, i find pattern matching and code heuristics approaches primitive and not suitable for
advanced binary analysis.

after few attempts i found a pretty good way to solve most issues. the analysis starts from the
first instruction, follows all direct jumps while marking them as either jump or function, then
indirect jump analysis computes register state and resolves some values, feeding back data to the
disassembler. when the CFG is stable, we can add more metadata to the basic blocks and create
functions based on branch analysis results.

this gives pretty good output for simple-ish codebase

### why not
of course there are tradeoffs compared to the other ways mentioned above. notably, the execution
time is much slower than just masking integers in the binary, as well as memory usage.

great amount of the CPU time is spent for various safety checks, because having broken CFG will
give invalid results

### TODO
as much as i hate heuristics, we can't really avoid them. something like this won't work and the
actual function won't be disassembled, unless something calls it directly

```c
static fn_t g_fn;

int main() {
  g_fn = ...;
  g_fn();
}
```

some solutions i have in mind:
1. check what is passed to function params, if it's something like `f(fn_at_0x1337)` then it
should queue the VA and try to disassemble it. now when it tries to disassemble, how do we know
if it's junk or actual function? perhaps code heuristics? no idea.
2. add some function signature database which has common prologues. but it feels like a bad idea

i tend to think the first idea is better, but some junk filter should be implemented.

other important todos:
- more self-tests. especially for phase 2
- better performance (mostly by using `HashMap` in hot paths)
- smaller structs (basicblock uses 272 bytes just for one instance!)
- some kind of refresh API to be able to feed back data from the user
- some abstraction over phase 1 to support arm64
- better docs
- reference implementation (i'm thinking about gui or tui)
- ...

### contributing
there are some preferences about code and i want you to follow them in case you're going to
contribute. some of these are not really idiomatic rust, but i don't care.

- nesting is preferred, unless it would look better without nesting. it makes easier to read
complex code for me

e.g. bad:
```rust
if let Some(...) = ... {
  f();
  // ...

  return Ok(());
}

Err(...)
```

instead do this:
```rust
if let Some(...) = ... {
  f();

  // ...
  Ok(())
} else {
  Err(...)
}
```

the first option is fine for very complex loops though.

bad:
```rust
if a {
  do_something();
} else {
  do_else();

  if b {
    do_something_else();
  } else {
    do_whatever();
  }
}
```

good:
```rust
if a {
  do_something();
  return;
}

do_else();

if b {
  do_something_else();
  return;
}

do_whatever();
```

- no allocs where you can avoid them. using `HashMap` or any other temporary struct for
performance is fine as long as it doesn't take too much memory though. cursed code is fine as
long as it helps to avoid allocs and you can guess what it does. the good example is
`phase1::branch_analysis::BranchAnalysis::all_jumps_for` function.
- no `dyn`. ever. only generics and enum dispatch are allowed
- no `#[derive(Copy)]` unless the type is <= 8 bytes
- no `RwLock`, `RefCell`, `(A)Rc`, etc. keep it simple. if you find that something needs interior
mutability then something is wrong
- no `unsafe`. ever.
- avoid `.clone()` where possible
- if you're sure the branch will not be entered then `unreachable!` is fine and preferred over
`Err`. same thing about `.expect(...)`.
- no `.unwrap()`. generic errors are bad and hard to debug. `.expect(...)` is fine though
- add logs where applicable. they shouldn't be in every branch, but if something may fail or
useful for debugging then add logs.
- most of the logs should be `trace` or `debug`. errors propagated with `Err` should NOT be logged
- logs ideally shouldn't alloc
- don't abuse iterators. `while let Some(...) = queue.pop()` is better than
`(0..usize::MAX).for_each(|i| ...)`
- make sure to comment each function (even if it's internal). no need to comment something
obvious like `new` though.
- document public functions
- comments as well as docs are *lowercase*.
- comment each `.clone()`, even if it's something cheap like 16 byte struct
- do *not* expose unneeded structs to the user. everything should be handed with views or global
analyzer struct.
- if the struct is internal, do not add useless getters. instead mark field as `pub`.

bad:
```rust
struct A {
  b: C;
}

impl A {
  fn b(&self) -> &C { &self.b }
}
```

good:
```rust
struct A {
  pub b: C;
}
```
- if the struct is both exposed as public and used internally, prefer fields over getters.
- if the struct is public, do *not* mark fields as public. `pub(crate)` is fine though.
- prefer constructors (so `new`) over raw struct creation
- inline format specifiers where possible.

bad:
```rust
debug!("a = {}, b = {}", a, b.len());
```

good:
```rust
debug!("a = {a}, b = {}", b.len());
```

- do *not* return reference to primitives or less than 8 bytes structs/enums in getters
- something else i definitely forgot, but the code style should be pretty much consistent, so you
can use that as somewhat good reference

## license
[AGPLv3](./LICENSE)
