# Minimal External LKM Actions Build

这个仓库现在是“最简单的外置 LKM 模块”示例

What this workflow does:

1. Uses the same `ddk-min` container family used by KernelSU.
2. Detects the prepared kernel build directory inside the container.
3. Builds the out-of-tree module in `module/` with kbuild.
4. Uploads the generated `hello.ko` as a workflow artifact.

Files:

- `.github/workflows/build-lkm.yml`
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

External module build command used by the workflow:

- `make -C <kernel-build-dir> M=$GITHUB_WORKSPACE/module CC=clang LLVM=1 modules`

If you want, the next step can be replacing `hello.c` with your real module source and expanding `module/Makefile`.

Userspace loader (use `init_module` syscall):

- Build: `make -C loader`
- Load ko: `sudo ./loader/init_module_loader ./module/hello.ko`
- Flow: parse ELF from ko buffer, relocate undefined symbols from `/proc/kallsyms` (`SHN_UNDEF -> SHN_ABS + st_value=addr`), then call `init_module`
- Params: if `/ksu_allow_shell` exists, loader auto-adds `allow_shell=1`; extra params can still be passed as second argument
