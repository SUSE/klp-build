# Packaging klp-build in Open Build Service

This directory contains the files needed to build klp-build as an RPM package
using the [Open Build Service](https://build.opensuse.org) (OBS).

## Step-by-Step Build Instructions

### 1. Generate the source tarball

From the root of the klp-build git repository:

```bash
VERSION="2.0.0"

git archive --format=tar.gz \
    --prefix="klp-build-${VERSION}/" \
    -o "klp-build-${VERSION}.tar.gz" \
    HEAD
```

### 2. Update the spec version

Edit `packaging/klp-build.spec` and update the version

### 3. Update the changelog

```bash
cd packaging
osc vc klp-build.changes
```

### 4. Checkout the OBS package

```bash
osc checkout home:<username>:klp-tools klp-build
cd home:<username>:klp-tools/klp-build
```

### 5. Copy files into the OBS package

```bash
cp /path/to/klp-build/packaging/klp-build.spec .
cp /path/to/klp-build/packaging/klp-build.changes .
cp /path/to/klp-build/klp-build-<VERSION>.tar.gz .
```

### 7. Submit to OBS

```bash
osc addremove
osc commit
```
