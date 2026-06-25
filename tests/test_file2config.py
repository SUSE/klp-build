# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2026 SUSE
# Author: Fernando Gonzalez <fernando.gonzalez@suse.com>

from pathlib import Path

from klpbuild.klplib.codestream import Codestream
from klpbuild.klplib.file2config import (
    _filter_path,
    _get_arch_in_path,
    _sanitize_config,
    _load_makefile,
    _find_config,
    find_file_config,
    find_files_config,
)


CS = Codestream("15.5u15", kernel="5.14.21-150500.55.68")


# -- _filter_path -------------------------------------------------------------


def test_filter_path_no_match():
    assert _filter_path("net/tls/tls_main.c") == "net/tls/tls_main.c"


def test_filter_path_blacklist_match():
    assert _filter_path("drivers/gpu/drm/amd/display/dc/core/dc.c") == "drivers/gpu/drm/amd/amdgpu/amdgpu_irq.c"


def test_filter_path_blacklist_amdgpu_not_matched():
    assert _filter_path("drivers/gpu/drm/amd/amdgpu/amdgpu_device.c") == "drivers/gpu/drm/amd/amdgpu/amdgpu_device.c"


# -- _get_arch_in_path --------------------------------------------------------


def test_get_arch_in_path_s390():
    assert _get_arch_in_path("arch/s390/crypto/aes_s390.c") == "s390x"


def test_get_arch_in_path_x86():
    assert _get_arch_in_path("arch/x86/kernel/cpu/common.c") == "x86_64"


def test_get_arch_in_path_powerpc():
    assert _get_arch_in_path("arch/powerpc/kernel/entry_64.c") == "ppc64le"


def test_get_arch_in_path_none():
    assert _get_arch_in_path("net/tls/tls_main.c") is None


# -- _sanitize_config ---------------------------------------------------------


def test_sanitize_config_standard():
    assert _sanitize_config("obj-$(CONFIG_TLS)") == "CONFIG_TLS"


def test_sanitize_config_with_plus_equals():
    assert _sanitize_config("obj-$(CONFIG_TLS) +=") == "CONFIG_TLS"


def test_sanitize_config_curly_braces():
    assert _sanitize_config("obj-${CONFIG_TLS}") == "CONFIG_TLS"


def test_sanitize_config_setup_prefix():
    assert _sanitize_config("setup-$(CONFIG_X86_APM_BOOT)") == "CONFIG_X86_APM_BOOT"


def test_sanitize_config_no_config():
    assert _sanitize_config("obj-y") is None


# -- _load_makefile ------------------------------------------------------------


def test_load_makefile_not_exists():
    assert _load_makefile(CS, Path("nonexistent/dir/Makefile")) == []


def test_load_makefile_simple():
    lines = _load_makefile(CS, Path("net/tls/Makefile"))
    assert any("obj-$(CONFIG_TLS)" in line for line in lines)


def test_load_makefile_multiline_continuation():
    lines = _load_makefile(CS, Path("kernel/Makefile"))
    obj_y_line = [line for line in lines if line.startswith("obj-y")][0]
    assert "fork.o" in obj_y_line
    assert "async.o" in obj_y_line
    assert "\\" not in obj_y_line


# -- _find_config --------------------------------------------------------------


def test_find_config_simple_obj_config():
    config, obj = _find_config(CS, Path("net/tls"), "tls.o", 0)
    assert config == "CONFIG_TLS"
    assert obj == "net/tls/tls"


def test_find_config_composite_object():
    config, obj = _find_config(CS, Path("net/tls"), "tls_main.o", 0)
    assert config == "CONFIG_TLS"
    assert obj == "net/tls/tls"


def test_find_config_obj_y_recurse_to_parent():
    config, obj = _find_config(CS, Path("kernel"), "fork.o", 0)
    assert config == "CONFIG_SUSE_KERNEL"
    assert obj == "vmlinux"


def test_find_config_root_fallback():
    config, obj = _find_config(CS, Path("."), "anything.o", 0)
    assert config == "CONFIG_SUSE_KERNEL"
    assert obj == "vmlinux"


def test_find_config_not_found_in_makefile():
    config, obj = _find_config(CS, Path("net/tls"), "nonexistent.o", 0)
    assert config is None
    assert obj == ""


def test_find_config_block_simple():
    config, obj = _find_config(CS, Path("block"), "bsg.o", 0)
    assert config == "CONFIG_BLK_DEV_BSG_COMMON"
    assert obj == "block/bsg"


def test_find_config_setup_y_target():
    config, obj = _find_config(CS, Path("arch/x86/boot"), "cpuflags.o", 0)
    assert config == "CONFIG_SUSE_KERNEL"
    assert obj == "vmlinux"


def test_find_config_kbuild_scattered():
    config, obj = _find_config(CS, Path("arch/x86/kernel/cpu"), "scattered.o", 0)
    assert config == "CONFIG_SUSE_KERNEL"
    assert obj == "vmlinux"


def test_find_config_dir_ref_not_in_makefile():
    config, obj = _find_config(CS, Path("arch/x86"), "boot/", 0)
    assert config == "CONFIG_SUSE_KERNEL"
    assert obj == "vmlinux"


# -- find_file_config ----------------------------------------------------------


def test_find_file_config_header_skipped():
    assert find_file_config(CS, "include/linux/tls.h") == ("", "")


def test_find_file_config_simple():
    config, obj = find_file_config(CS, "net/tls/tls.c")
    assert config == "CONFIG_TLS"
    assert obj == "net/tls/tls"


def test_find_file_config_composite_object():
    config, obj = find_file_config(CS, "net/tls/tls_main.c")
    assert config == "CONFIG_TLS"
    assert obj == "net/tls/tls"


def test_find_file_config_blacklisted_path():
    config, _ = find_file_config(CS, "drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.c")
    assert config == "CONFIG_DRM_AMDGPU"


def test_find_file_config_no_config_found():
    assert find_file_config(CS, "net/tls/nonexistent.c") == ("", "")


def test_find_file_config_arch_single_correct_arch():
    config, obj = find_file_config(CS, "arch/s390/crypto/aes_s390.c")
    assert config == "CONFIG_CRYPTO_AES_S390"
    assert obj == "arch/s390/crypto/aes_s390"


def test_find_file_config_builtin_to_root():
    config, obj = find_file_config(CS, "kernel/fork.c")
    assert config == "CONFIG_SUSE_KERNEL"
    assert obj == "vmlinux"


def test_find_file_config_strips_whitespace():
    config, _ = find_file_config(CS, "  net/tls/tls.c  ")
    assert config == "CONFIG_TLS"


def test_find_file_config_cpuflags():
    config, obj = find_file_config(CS, "arch/x86/boot/cpuflags.c")
    assert config == "CONFIG_X86_64"
    assert obj == "vmlinux"


def test_find_file_config_scattered():
    config, obj = find_file_config(CS, "arch/x86/kernel/cpu/scattered.c")
    assert config == "CONFIG_X86_64"
    assert obj == "vmlinux"


def test_find_file_config_obj_prefix_variable():
    config, _ = find_file_config(CS, "arch/x86/boot/compressed/sev.c")
    assert config == "CONFIG_AMD_MEM_ENCRYPT"


def test_find_file_config_nested_subdir():
    config, _ = find_file_config(CS, "drivers/net/ethernet/mellanox/mlx5/core/steering/dr_domain.c")
    assert config == "CONFIG_MLX5_SW_STEERING"


# -- find_files_config ---------------------------------------------------------


def test_find_files_config_empty_list():
    configs, missing = find_files_config(CS, [])
    assert not configs
    assert not missing


def test_find_files_config_single_found():
    configs, missing = find_files_config(CS, ["net/tls/tls.c"])
    assert "net/tls/tls.c" in configs
    assert configs["net/tls/tls.c"]["conf"] == "CONFIG_TLS"
    assert not missing


def test_find_files_config_single_missing():
    configs, missing = find_files_config(CS, ["include/linux/tls.h"])
    assert not configs
    assert missing == ["include/linux/tls.h"]


def test_find_files_config_mixed():
    configs, missing = find_files_config(CS, ["net/tls/tls.c", "include/linux/tls.h", "net/tls/nonexistent.c"])
    assert "net/tls/tls.c" in configs
    assert "include/linux/tls.h" in missing
    assert "net/tls/nonexistent.c" in missing
