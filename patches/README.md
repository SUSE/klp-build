klp-convert
-----------

Since we have CET on newer kernels, we can't use kallsyms to find addresses for
private symbols. And as klp-convert is not upstream yet, you will need to apply
the current version of it from this 
[mbox
file](./v2_20240516_lhruska_livepatch_klp_convert_tool_minimal_version.mbx),
when creating livepatches for upstream kernels.

IPA-clones
----------

To correctly find where symbols were inlined we use a feature from gcc to
generate a report of Inter Process Analysis (IPA). This is why we have this [patch](./0001-Add-ipa-clones-and-flive-patching-GCC-flags-for-live.patch).

clang-extract vs LLVM problems
------------------------------

While testing clang-extract on upstream kernels, we found an issue while parsing
file ``include/linux/compiler_attributes.h``. We opened a bug on LLVM project
but we haven't heard from them yet. For now we disable the macro ``c
__compiletime_error`` macro to avoid this problem using this [patch](./0001-compiler_attributes.h-Disable-__compiletime_error-ma.patch).
