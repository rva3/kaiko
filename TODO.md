as much as i hate heuristics, we can't really avoid them. something like this won't work and the
actual function won't be disassembled, unless something calls it directly

```c
static fn_t g_fn;

int main() {
  g_fn = ...;
  g_fn();
}
```

some ideas:
1. check what is passed to function params, if it's something like `f(fn_at_0x1337)` then it
should queue the VA and try to disassemble it. now when it tries to disassemble, how do we know
if it's junk or actual function? perhaps code heuristics? no idea.
2. add some function signature database which has common prologues. but it feels like a bad idea

other important todos:
- more self-tests. especially for phase 2
- better performance (mostly by using `HashMap` in hot paths)
- smaller structs (basicblock uses 272 bytes just for one instance!)
- some kind of refresh API to be able to feed back data from the user
- some abstraction over phase 1 to support arm64
- better docs
- reference usage (gui or tui)
- ...
