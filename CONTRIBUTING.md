there are some preferences about the code:

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

- no allocs if it's possible to avoid them. using `HashMap` or any other temporary struct for
performance is fine as long as it doesn't take too much memory though. cursed code is fine as
long as it helps to avoid allocs. the good example is a
`phase1::branch_analysis::BranchAnalysis::all_jumps_for` function.
- no `dyn`. ever. only generics and enum dispatch are allowed
- no `#[derive(Copy)]` unless the type is <= 8 bytes
- no `RwLock`, `RefCell`, `(A)Rc`, etc. keep it simple.
- no `unsafe`. ever.
- avoid `.clone()` where possible
- if the branch will not be entered then `unreachable!` is fine and preferred over
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
- ...
