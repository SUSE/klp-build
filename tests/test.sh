#!/bin/bash
# Author: Marcos Paulo de Souza <mpdesouza@suse.com>
#
# Make sure that clang-extract generates compilable code for known functions,
# and does not exceed the current number of lines of code generated.

# Stop on the first error
set -e

# KLP_WORK_DIR is used bu klp-build tool, that should contain the patches
# mentioned in the README, plus having the compiled modules and vmlinux
export KLP_WORK_DIR=/home/mpdesouza/klp/livepatches
KLP_GIT_SOURCE=/home/mpdesouza/git/linux

setup_extract_count()
{
	local lp_name="$1"
	shift
	local max_lines="$1"
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
	echo "Extracting $lp_name"

	rm -rf $KLP_WORK_DIR/$lp_name
	if [ -n "$mod_" ]; then
		klp-build setup --name $lp_name --kdir --data-dir $KLP_GIT_SOURCE --conf $conf_ --module $mod_ --file-funcs $file_ $@
	else
		klp-build setup --name $lp_name --kdir --data-dir $KLP_GIT_SOURCE --conf $conf_ --file-funcs $file_ $@
	fi
	klp-build extract --name $lp_name --type ce
	# Check if the extracted code compiles
	make -C $KLP_WORK_DIR/$lp_name/ce/linux/lp

	nlines=$(cat $KLP_WORK_DIR/$lp_name/ce/linux/lp/livepatch_${lp_name}.c | wc -l)
	echo "LoC: $nlines"
	echo "LoC expected: $max_lines"
	if [ "$nlines" -gt "$max_lines" ]; then
		echo "ERROR: Generated file for $lp_name contains $nlines LoC, but should contain < $max_lines LoC"
		exit 1
	fi
}

LPS=$(cat << EOF
lp_proc_cmdline_show		68	CONFIG_PROC_FS	vmlinux		fs/proc/cmdline.c \
									cmdline_proc_show
lp_cve_2021_22600		655	CONFIG_UNIX	af_packet	net/packet/af_packet.c \
									packet_set_ring
lp_ipv6_route_multipath_add	443	CONFIG_IPV6	ipv6		net/ipv6/route.c \
									ip6_route_multipath_add
lp_cve_2024_27398		88	CONFIG_BT	bluetooth	net/bluetooth/sco.c \
									sco_sock_timeout
lp_cve_2024_26923		171	CONFIG_UNIX	vmlinux		net/unix/garbage.c \
									unix_gc
lp_cve_2024_35950		842	CONFIG_DRM	vmlinux		drivers/gpu/drm/drm_client_modeset.c \
									drm_client_modeset_probe
lp_cve_2021_47378		958	CONFIG_NVME_RDMA nvme-rdma	drivers/nvme/host/rdma.c \
									nvme_rdma_free_queue \
									nvme_rdma_cm_handler
lp_cve_2021_47402		197    CONFIG_NET_CLS_FLOWER cls_flower net/sched/cls_flower.c \
									fl_walk
lp_cve_2024_40909		143	CONFIG_BPF_SYSCALL  vmlinux	kernel/bpf/syscall.c \
									bpf_link_free
lp_cve_2024_0775		2113	CONFIG_EXT4_FS	ext4		fs/ext4/super.c \
									ext4_reconfigure
EOF
)

while IFS=, read lp_name loc config mod file funcs; do
	setup_extract_count $lp_name $loc $config $mod $file $funcs
done <<< "$LPS"
