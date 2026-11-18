# Local development

`rust-toolchain.toml` pins the dev toolchain at 1.100. The minimum supported version is 1.98 (`rust-version` in the workspace manifest). `cargo +1.98 check` is the MSRV check. That selector is the toolchain named `1.98`, which is not the same install as `1.98.0`, so both toolchains need to be installed:

```sh
rustup toolchain install 1.100.0 --profile minimal --component rustfmt,clippy,llvm-tools-preview
rustup toolchain install 1.98
```

Install the CI tools with the pinned toolchain. `cargo-shear` 1.14.1 does not build on rustc 1.91, which is what an un-updated `stable` may still be:

```sh
cargo +1.100.0 install --locked cargo-nextest cargo-hack cargo-deny cargo-shear cargo-llvm-cov
```

`actionlint` checks the workflow files; install it with your package manager.

The commands CI runs are listed in `AGENTS.md`. Run that list on a clean tree before pushing. Docker is required only for `cargo nextest run --workspace --profile integration`. The default nextest profile does not run those tests.

The live Apple test account is `~/.config/ibridge/test-account.env`. Do not create a repo `.env`, and do not print the password.

Install BeautifulRust with the pinned command in `AGENTS.md`:

```sh
npx skills add morganlinton/BeautifulRust@b9718436d77ee7bcf17cdcb6aa27628feb95d97a
```

Do not enable its remote MCP server.

## Tests with a paused clock

`#[tokio::test(start_paused = true)]` freezes Tokio's clock. A test moves it with `tokio::time::advance`. The paused clock does not stop real work.

**`tokio::fs` runs on the blocking pool.** Every `tokio::fs` call, and `spawn_blocking`, hands the work to a separate thread. A fixed number of `yield_now().await` calls only lets other tasks run; it does not wait for that thread. On a slow or busy machine, such as GitHub's 2-core Linux runner, the test looks at the disk before the work has finished. The backup schedule tests in `crates/ibridge-hosted/src/backup.rs` failed this way, with `the first copy is taken at once` and `a restart does not take an extra copy`, while they usually passed on a quiet Mac (a cold-build run on a Mac failed too).

What to do:

- Wait for something the code under test does, not for a number of yields. In the backup tests the clock closure counts its reads, and `settle(&reads, n)` waits until the count reaches `n`. The code reads the clock right before it sleeps, so the count says it is waiting again. A test that asserts nothing happened (no extra copy after a restart) waits on the same signal first. Otherwise it passes because the code has not run yet.
- Poll with `yield_now().await` and a short `std::thread::sleep`, and bound the poll by real time (`std::time::Instant`), with a message that says what never happened. Do not poll with `tokio::time::sleep`; under a paused clock it moves the clock the test is checking.

What never to do: raise the yield count, add a retry, loosen an assertion, or add `#[ignore]` to get a green run. They hide the race and it comes back on a slower machine.

Find a flake of this kind by loading the machine and repeating the tests. Twelve busy loops reproduced the failure on a Mac in 6 of 100 runs; the first run after a cold build also failed:

```sh
for i in $(seq 12); do (yes >/dev/null &); done
cargo nextest run -p ibridge-hosted -E 'test(/backup::tests/)' --no-fail-fast --stress-count 300
pkill -x yes
```

Stop the loops with `pkill -x yes` when it ends, or the machine stays loaded. A test counts as fixed when every iteration passes under that load. To match CI more closely, run the tests in a Linux container with two CPUs (`docker run --cpus=2`, behind `lockf -k <repo>/.git/ibridge-docker.lock`).

Traps:

- A quiet machine hides the race. 50 stress iterations with no load all passed. Always add load.
- `--stress-count` runs the whole filtered set each iteration. A failure's name tells which test; do not assume it is the one named in CI. The rotation test failed too.
- A fixed `std::thread::sleep` in a test is also a guess, not a fix. Wait for the signal.
