#!/bin/bash
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>
#
# Make sure that clang-extract generates compilable code for known functions,
# and does not exceed the current number of lines of code generated.

# Stop on the first error
set -e

# KLP_WORK_DIR is used bu klp-build tool, that should contain the patches
# mentioned in the README, plus having the compiled modules and vmlinux
export KLP_WORK_DIR=/home/mpdesouza/kgr/livepatches
KLP_GIT_SOURCE=/home/mpdesouza/git/linux

setup_extract_count()
{
	local max_lines="$1"
	shift
	local patch_="$1"
	shift
	local conf_="$1"
	shift
	local mod_="$1"
	shift
	local file_="$1"
	shift
	# Now $@ will contain all symbols to be extracted

	echo
	echo
	echo "Extracting $patch_"

	rm -rf $KLP_WORK_DIR/$patch_
	if [ -n "$mod_" ]; then
		klp-build setup --name $patch_ --kdir --data-dir $KLP_GIT_SOURCE --conf $conf_ --module $mod_ --file-funcs $file_ $@
	else
		klp-build setup --name $patch_ --kdir --data-dir $KLP_GIT_SOURCE --conf $conf_ --file-funcs $file_ $@
	fi
	klp-build extract --name $patch_ --type ce
	# Check if the extracted code compiles
	make -C $KLP_WORK_DIR/$patch_/ce/linux/lp

	nlines=$(cat $KLP_WORK_DIR/$patch_/ce/linux/lp/livepatch_${patch_}.c | wc -l)
	if [ "$nlines" -gt "$max_lines" ]; then
		echo "ERROR: Generated file for $patch_ contains $nlines LoC, but should contain < $max_lines LoC"
		exit 1
	fi
}

setup_extract_count "105" lp_proc_cmdline_show	CONFIG_PROC_FS	""  fs/proc/cmdline.c	cmdline_proc_show

setup_extract_count "640" lp_cve_2021_22600	CONFIG_UNIX	af_packet  net/packet/af_packet.c	packet_set_ring

setup_extract_count "700" lp_ipv6_route_multipath_add	CONFIG_IPV6	ipv6	net/ipv6/route.c	ip6_route_multipath_add

setup_extract_count "88" lp_cve_2024_27398	CONFIG_BT	bluetooth  net/bluetooth/sco.c sco_sock_timeout

setup_extract_count "170" lp_cve_2024_26923	CONFIG_UNIX	""	net/unix/garbage.c	unix_gc

# FIXME: we should take a look into it to reduce the number of lines generated.
setup_extract_count "830" lp_cve_2024_35950	CONFIG_DRM	""	drivers/gpu/drm/drm_client_modeset.c	drm_client_modeset_probe

# FIXME: we should take a look into it to reduce the number of lines generated.
setup_extract_count "2832" lp_cve_2021_47378	CONFIG_NVME_RDMA	nvme-rdma	drivers/nvme/host/rdma.c	nvme_rdma_free_queue nvme_rdma_cm_handler
