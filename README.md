# Minimal External LKM Actions Build

这个仓库现在是“最简单的外置 LKM 模块”示例

What this workflow does:

1. Uses the same `ddk-min` container family used by KernelSU.
2. Detects the prepared kernel build directory inside the container.
3. Builds the out-of-tree module in `module/` with kbuild.
4. Builds Android loader tools in `loader/` via NDK (`init_module_loader_arm64`, `hello_comm_test_arm64`).
5. Uploads the generated `hello.ko` and loader binaries as workflow artifacts.
6. Auto-triggers `Pull Latest KO` to fetch the newest successful build artifact and republish it as `latest-ko`.

Files:

- `.github/workflows/build-lkm.yml`
- `.github/workflows/pull-latest-ko.yml`
- `module/hello.c`
- `module/Makefile`
- `loader/init_module_loader.c`
- `loader/Makefile`

How to use:

1. Push this repository to GitHub.
2. Open `Actions`.
3. Run `Build External LKM`.
4. Select the target `kmi`.
5. Download the generated `.ko` artifact after the job finishes.

Download latest ko to local:

1. Run: `./scripts/download-latest-ko.sh`
2. Files will be saved to:
   - `out/latest.ko`
   - `out/latest_init_module_loader_arm64` (when artifact includes loader)
   - `out/latest_hello_comm_test_arm64` (when artifact includes loader)
   (or pass custom output dir: `./scripts/download-latest-ko.sh <dir>`)
3. Script will prefer artifact `latest-ko`, fallback to newest `*-lkm`
4. Script can auto-read GitHub credential from your git credential helper (e.g. macOS keychain)
5. If private repo or API rate limit: set token first `export GITHUB_TOKEN=<token>`

External module build command used by the workflow:

- `make -C <kernel-build-dir> M=$GITHUB_WORKSPACE/module CC=clang LLVM=1 modules`

If you want, the next step can be replacing `hello.c` with your real module source and expanding `module/Makefile`.

Userspace loader (use `init_module` syscall):

- Build: `make -C loader`
- Load ko: `sudo ./loader/init_module_loader ./module/hello.ko`
- Flow: parse ELF from ko buffer, relocate undefined symbols from `/proc/kallsyms` (`SHN_UNDEF -> SHN_ABS + st_value=addr`), then call `init_module`
- Params: if `/ksu_allow_shell` exists, loader auto-adds `allow_shell=1`; extra params can still be passed as second argument
