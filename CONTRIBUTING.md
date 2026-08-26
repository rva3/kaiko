there are some preferences about the code:

- use explicit if/else

bad:
```rust
if let Some(...) = ... {
  f();
  // ...

  return Ok(());
}

Err(...)
```

good:
```rust
if let Some(...) = ... {
  f();

  // ...
  Ok(())
} else {
  Err(...)
}
```

- no allocs unless it greatly speeds up lookup (i.e. reverse HashMap is fine)
- no `dyn`. use generics or enum dispatch
- no `#[derive(Copy)]` unless the type is <= 16 (ideally 8) bytes
- no `RwLock`, `RefCell`, `(A)Rc`, etc. keep it simple
- no fancy `.map_or`, `.map_or_else`, etc. it's really hard to read them
- no `unsafe`
- avoid `.clone()` on big types
- use `unreachable!(...)` if the branch is not expected to be executed
- prefer `.expect(...)` over `.unwrap()` for meaningful panic messages
- add `code: {var}` format when modifying files which operate on raw instructions. it's hard
to guess where the analyzer failed otherwise
- add logs in paths which can help with debugging
- errors propagated with `Err` should NOT be logged
- logs ideally shouldn't alloc
- document public functions
- comments as well as docs are *lowercase*
- comment each `.clone()`, even if it's something cheap like 16 byte struct
- do *not* expose unneeded structs to the user. everything should be handed with views or
global analyzer struct
- if the struct is internal, use `pub` instead of getter/setter for the fields
- if the struct is public, do *not* mark fields as public
- if the struct is both exposed as public and used internally, prefer `pub` on fields over
getters/setters
- prefer constructors over raw struct creation
- inline format specifiers where possible

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
