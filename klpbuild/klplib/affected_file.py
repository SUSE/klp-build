# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2026 SUSE
# Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>

from enum import Enum
from pathlib import PurePosixPath

from klpbuild.klplib.utils import ARCHS


class AffectedModule:
    """
    A kernel object potentially patched by a livepatch.

    Covers both loadable ``.ko`` modules (e.g. ``"fs/ext4/ext4"``) and
    ``vmlinux`` itself.

    The same module instance is shared by every source
    file compiled into it.
    """

    VMLINUX = "vmlinux"

    def __init__(self, name: str):
        self.name = name                            # e.g. "fs/ext4/ext4" or "vmlinux"
        self.supported: bool | None = None          # None = not yet checked
        self.blacklisted: bool = False              # not supported for livepatching
        self._obj_paths: dict[str, str] = {}        # arch -> resolved on-disk path

    @classmethod
    def vmlinux(cls) -> "AffectedModule":
        """
        Create the canonical :attr:`VMLINUX` :class:`AffectedModule`.
        """
        m = cls(cls.VMLINUX)
        m.supported = True
        return m

    @property
    def is_vmlinux(self) -> bool:
        """``True`` if this module represents the kernel image (``vmlinux``)."""
        return self.name == self.VMLINUX

    @property
    def lp_module_name(self) -> str:
        """
        Return the module name formatted for livepatch ``LP_MODULE``
        kallsyms lookup strings.
        """
        return PurePosixPath(self.name.replace("-", "_")).name

    def set_obj_path(self, arch: str, path: str) -> None:
        """Cache the resolved on-disk object path for ``arch``."""
        if arch not in ARCHS:
            raise ValueError(f"Unknown arch: {arch}")
        self._obj_paths[arch] = path

    def get_obj_path(self, arch: str) -> str | None:
        """Return the cached on-disk object path for ``arch``, or ``None``."""
        if arch not in ARCHS:
            raise ValueError(f"Unknown arch: {arch}")
        return self._obj_paths.get(arch)

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "AffectedModule":
        """Reconstruct an :class:`AffectedModule` from the dict produced by :meth:`to_dict`."""
        m = cls(name)
        m.supported   = data["supported"]
        m.blacklisted = data["blacklisted"]
        for arch, path in data["obj_paths"].items():
            m.set_obj_path(arch, path)
        return m

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialization."""
        return {
            "supported": self.supported,
            "blacklisted": self.blacklisted,
            "obj_paths": dict(self._obj_paths),
        }

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AffectedModule):
            return NotImplemented
        return self.name == other.name

    def __hash__(self) -> int:
        return hash(self.name)

    def __str__(self) -> str:
        # Renders as the bare module name (e.g. "vmlinux" or "fs/ext4/ext4")
        # so f-strings can interpolate an :class:`AffectedModule` directly into
        # output paths and template lines.
        return self.name

    def __repr__(self) -> str:
        return (f"AffectedModule(name={self.name!r}, "
                f"supported={self.supported!r}, "
                f"blacklisted={self.blacklisted!r})")


class ConfigState(Enum):
    """
    Possible values of a kernel configuration option on a given architecture.

    The ``value`` of each member matches the character used by the kernel build
    system.
    """
    NOT_SET = "n"
    MODULE  = "m"
    BUILTIN = "y"


class AffectedConfig:
    """
    A kernel configuration option (e.g. ``CONFIG_FOO``) together with its
    state on each supported architecture.

    Architectures that were never set are reported as
    :attr:`ConfigState.NOT_SET`.
    """

    def __init__(self, config_name: str,
                 arch_values: dict[str, str] | None = None):
        if not config_name.startswith("CONFIG_"):
            raise ValueError(
                f"Invalid config '{config_name}': missing CONFIG_ prefix")

        self.config_name = config_name
        self._values: dict[str, ConfigState] = {}

        for arch, value in (arch_values or {}).items():
            self.set_arch(arch, ConfigState(value))

    def set_arch(self, arch: str, value: ConfigState) -> None:
        """
        Set the configuration state for ``arch``.

        Setting an arch to :attr:`ConfigState.NOT_SET` removes it from the
        internal mapping so that :meth:`archs` and :meth:`is_set` keep their
        natural meaning.
        """
        if arch not in ARCHS:
            raise ValueError(f"Unknown arch: {arch}")

        if value is ConfigState.NOT_SET:
            self._values.pop(arch, None)
        else:
            self._values[arch] = value

    def get_arch(self, arch: str) -> ConfigState:
        """
        Return the :class:`ConfigState` for ``arch``, defaulting to
        :attr:`ConfigState.NOT_SET` when the arch was never set.
        """
        if arch not in ARCHS:
            raise ValueError(f"Unknown arch: {arch}")
        return self._values.get(arch, ConfigState.NOT_SET)

    def archs(self) -> set[str]:
        """Return the set of architectures where this config is set (``y`` or ``m``)."""
        return set(self._values)

    # NOTE: not yet used
    def is_builtin_on_any(self) -> bool:
        """``True`` if the config is built into vmlinux on at least one arch."""
        return ConfigState.BUILTIN in self._values.values()

    def is_module_on_any(self) -> bool:
        """``True`` if the config is built as a module on at least one arch."""
        return ConfigState.MODULE in self._values.values()

    def is_set(self) -> bool:
        """``True`` if the config has any value (``y`` or ``m``) on any arch."""
        return bool(self._values.keys())

    @classmethod
    def from_dict(cls, name: str, data: dict[str, str]) -> "AffectedConfig":
        """Reconstruct an :class:`AffectedConfig` from the dict produced by :meth:`to_dict`."""
        return cls(name, data)

    def to_dict(self) -> dict[str, str]:
        """Return a plain ``{arch: 'y'|'m'}`` dict suitable for JSON serialization."""
        return {arch: state.value for arch, state in self._values.items()}

    def __bool__(self) -> bool:
        return self.is_set()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AffectedConfig):
            return NotImplemented
        return (self.config_name == other.config_name
                and self._values == other._values)

    def __hash__(self) -> int:
        return hash((self.config_name, frozenset(self._values.items())))

    def __str__(self) -> str:
        # Concise human-readable form for log output and report keys,
        # e.g. "CONFIG_FOO(x86_64=m, s390x=y)" or "CONFIG_FOO(not set)".
        if self._values:
            archs = ", ".join(f"{a}={s.value}"
                              for a, s in sorted(self._values.items()))
            return f"{self.config_name}({archs})"
        return f"{self.config_name}(not set)"

    def __repr__(self) -> str:
        return f"AffectedConfig({self.config_name!r}, {self.to_dict()!r})"


class AffectedFile:
    """
    A Linux kernel source file modified we are livepatching.

    Holds analysis-phase metadata (the file's identity together with name-key
    cross-references into ``cs.configs`` and ``cs.modules`` and the set of
    symbols to be patched) and extraction-phase artifacts populated by
    ``klp-ccp`` during the extract step (see ``plugins/extract.py``).
    """

    def __init__(self, filename: str, *,
                 config_name: str | None = None,
                 module_name: str | None = None,
                 affected_symbols: set[str] | None = None):
        # Analysis-phase metadata
        self.filename = filename
        self.config_name = config_name              # key into cs.configs
        self.module_name = module_name              # key into cs.modules
        self.affected_symbols: set[str] = set(affected_symbols or ())

        # Extraction-phase artifacts (populated by extract.py)
        self.ibt: bool = False
        self.dup_symbols: list[str] = []
        self.ext_symbols: dict[str, list[str]] = {}     # module name → symbol list
        self.klpp_symbols: dict[str, str] = {}          # symbol name → prototype

    @classmethod
    def from_dict(cls, filename: str, data: dict) -> "AffectedFile":
        """Reconstruct an :class:`AffectedFile` from the dict produced by :meth:`to_dict`."""
        f = cls(
            filename,
            config_name=data["config_name"],
            module_name=data["module_name"],
            affected_symbols=set(data["affected_symbols"]),
        )
        f.ibt          = data["ibt"]
        f.dup_symbols  = list(data["dup_symbols"])
        f.ext_symbols  = dict(data["ext_symbols"])
        f.klpp_symbols = dict(data["klpp_symbols"])
        return f

    def to_dict(self) -> dict:
        """Return a plain dict suitable for JSON serialization."""
        return {
            "config_name": self.config_name,
            "module_name": self.module_name,
            "affected_symbols": sorted(self.affected_symbols),
            "ibt": self.ibt,
            "dup_symbols": list(self.dup_symbols),
            "ext_symbols": dict(self.ext_symbols),
            "klpp_symbols": dict(self.klpp_symbols),
        }

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AffectedFile):
            return NotImplemented
        return self.filename == other.filename

    def __hash__(self) -> int:
        return hash(self.filename)

    def __repr__(self) -> str:
        return (f"AffectedFile(filename={self.filename!r}, "
                f"config_name={self.config_name!r}, "
                f"module_name={self.module_name!r})")
