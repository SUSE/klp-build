# Setup
To create a new "livepatch project", use the setup command:

```sh
klp-build setup --bsc 1197597 --cve 2022-1048 \
		--work-dir /livepatches/ \
		--data /downloaded/rpms/dir \
		--upstream-commits 92ee3c60ec9fe64404dc035e7c41277d74aa26cb \
		--mod snd-pcm \
		--conf CONFIG_SND_PCM \
		--file-funcs all sound/core/pcm.c snd_pcm_attach_substream snd_pcm_detach_substream \
		--file-funcs all sound/core/pcm_native.c snd_pcm_hw_params snd_pcm_common_ioctl1
```

This command create a new directory in --work-dir argument, and the directory
name will be the bsc argument. Then klp-ccp is start executing for all affected
codestreams passed by file-funcs.

Explaining some arguments:
--data: location of ex-kernels, ipa-clones and kernel-rpms directory.
--mod: The module to be livepatched. If empty, vmlinux will be livepatched
       instead.
--file-funcs: The first argument is the kernel family (4.4, 4.12 or 5.3
	      currently), but can be set to all. The next argument needs to be a file, and the
	      following values are function names.

--work-dir and --data can be ommited the KLP_WORK_DIR and KLP_DATA_DIR env vars
are set.

# klp-ccp
At this point, klp-ccp will be run in parallel (nproc threads, one thread per
codestream). If desired, the setup command can skip running klp-ccp if the
--disable-ccp argument is passed. So, one can run klp-ccp alone by using:

```sh
klp-build run-ccp --work-dir /livepatches --bsc 1197597
```

After klp-ccp finishes executing for all codestreams/files, we can generate the
template livepatches by:

```sh
klp-build --work-dir /livepatches --bsc 1197596 --codestream 15.2u12
```

This command will create a new directory in the CWD named bsc1197596, containing
the generated templates/sources.

get-patches
===========

For downloading all the fixes in all CVE branches of kernel-source:

```sh
klp-build get-patches --work-dir /livepatches/ \
			--bsc 1111111 -u 92ee3c60ec9fe64404dc035e7c41277d74aa26cb
```

This command will create the fixes and the patches directories in
/livepatches/bsc1111111 directory. In patches, there would be a file for each
upstream commit passed as argument. In fixes dir, there will be one directory
for each CVE branch, and inside each CVE dir there will be the backported commit
related to that branch.
