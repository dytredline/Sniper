"""Descriptor-anchored, read-only access to an untrusted project tree.

``Path.resolve()`` and ``os.walk()`` do not keep the validated directory alive.
Another process can rename a parent after validation and put a symlink at the
same pathname.  :class:`ProjectTree` reaches an absolute root one component at
a time from ``/`` with ``O_DIRECTORY | O_NOFOLLOW`` and keeps that directory
descriptor open for the whole context.  Every later operation is relative to
that descriptor.

The module deliberately has no path-returning read API.  Walkers return strict
relative paths and file identity metadata; callers read those files through the
same :class:`ProjectTree` instance.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Collection, Iterator


MAX_RELATIVE_PATH_BYTES = 4096
MAX_READ_BYTES = 1_000_000_000
DEFAULT_MAX_ENTRIES = 100_000
DEFAULT_MAX_DEPTH = 64

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class ProjectTreeError(ValueError):
    """The requested tree operation was unsafe, invalid, or exceeded a limit."""


@dataclass(frozen=True)
class ProjectFile:
    """A regular file observed through an open project-directory descriptor."""

    path: PurePosixPath
    size: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int

    @property
    def name(self) -> str:
        return self.path.name


@dataclass(frozen=True)
class ProjectWalkEntry:
    """One deterministic directory result from :meth:`ProjectTree.walk`."""

    directory: PurePosixPath
    directories: tuple[PurePosixPath, ...]
    files: tuple[ProjectFile, ...]
    skipped_directories: tuple[PurePosixPath, ...] = ()


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _file_fingerprint(entry: ProjectFile) -> tuple[int, int, int, int, int]:
    return (entry.device, entry.inode, entry.size, entry.mtime_ns, entry.ctime_ns)


def _validate_limit(value: int, *, name: str, upper: int) -> int:
    if type(value) is not int or value < 0 or value > upper:
        raise ProjectTreeError(f"{name} geçersiz veya güvenli sınırı aşıyor.")
    return value


def _validated_component(value: str) -> str:
    """Return one separator-free path component through a recognized sanitizer."""
    component = os.path.basename(value)
    if (
        component != value
        or component in ("", ".", "..")
        or "\x00" in component
        or "\\" in component
        or len(os.fsencode(component)) > 255
    ):
        raise ProjectTreeError("Proje yolu geçersiz bir bileşen içeriyor.")
    return component


def _join(directory: PurePosixPath, name: str) -> PurePosixPath:
    return PurePosixPath(name) if directory == PurePosixPath(".") else directory / name


class ProjectTree:
    """A context-managed, descriptor-pinned view of one absolute project root."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        try:
            raw = os.fspath(root)
        except TypeError as exc:
            raise ProjectTreeError("Proje kökü mutlak bir metin yolu olmalı.") from exc
        if not isinstance(raw, str) or not raw or "\x00" in raw or "\\" in raw:
            raise ProjectTreeError("Proje kökü mutlak bir metin yolu olmalı.")
        if len(os.fsencode(raw)) > MAX_RELATIVE_PATH_BYTES or not raw.startswith("/"):
            raise ProjectTreeError("Proje kökü mutlak bir metin yolu olmalı.")
        if raw != "/":
            raw_components = raw.split("/")[1:]
            if not raw_components:
                raise ProjectTreeError("Proje kökü normalleştirilmiş mutlak bir yol olmalı.")
            components = [_validated_component(part) for part in raw_components]
        else:
            components = []
        self.root = Path(raw)
        self._root_components = tuple(components)
        self._root_fd: int | None = None

    @property
    def closed(self) -> bool:
        return self._root_fd is None

    def fileno(self) -> int:
        """Return the borrowed root descriptor; callers must not close it."""
        if self._root_fd is None:
            raise ProjectTreeError("Proje ağacı açık değil.")
        return self._root_fd

    def open(self) -> ProjectTree:
        if self._root_fd is not None:
            return self
        directory_fd: int | None = None
        try:
            directory_fd = os.open("/", _DIR_FLAGS)
            for component in self._root_components:
                safe_component = os.path.basename(component)
                if safe_component != component:
                    raise ProjectTreeError("Proje yolu geçersiz bir bileşen içeriyor.")
                next_fd = os.open(safe_component, _DIR_FLAGS, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
                raise ProjectTreeError("Proje kökü normal bir dizin değil.")
        except ProjectTreeError:
            if directory_fd is not None:
                os.close(directory_fd)
            raise
        except OSError as exc:
            if directory_fd is not None:
                os.close(directory_fd)
            raise ProjectTreeError("Proje kökü değişti veya sembolik bağ içeriyor.") from exc
        self._root_fd = directory_fd
        return self

    def close(self) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def __enter__(self) -> ProjectTree:
        return self.open()

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    @staticmethod
    def _relative_parts(relative: str | os.PathLike[str] | ProjectFile) -> tuple[str, ...]:
        value: object = relative.path.as_posix() if isinstance(relative, ProjectFile) else relative
        try:
            raw = os.fspath(value)  # type: ignore[arg-type]
        except TypeError as exc:
            raise ProjectTreeError("Göreli proje yolu geçersiz.") from exc
        if not isinstance(raw, str) or not raw or "\x00" in raw or "\\" in raw or raw.startswith("/"):
            raise ProjectTreeError("Göreli proje yolu geçersiz.")
        if len(os.fsencode(raw)) > MAX_RELATIVE_PATH_BYTES:
            raise ProjectTreeError("Göreli proje yolu çok uzun.")
        parts = tuple(_validated_component(part) for part in raw.split("/"))
        return parts

    def _duplicate_root(self) -> int:
        try:
            fd = os.dup(self.fileno())
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                os.close(fd)
                raise ProjectTreeError("Proje kökü normal bir dizin değil.")
            return fd
        except ProjectTreeError:
            raise
        except OSError as exc:
            raise ProjectTreeError("Proje kökü kullanılamıyor.") from exc

    def duplicate(self) -> ProjectTree:
        """Return an independently owned view pinned to the same open root."""
        duplicate = ProjectTree(self.root)
        duplicate._root_fd = self._duplicate_root()
        return duplicate

    def _open_file(self, relative: str | os.PathLike[str] | ProjectFile) -> tuple[int, ProjectFile | None]:
        expected = relative if isinstance(relative, ProjectFile) else None
        parts = self._relative_parts(relative)
        directory_fd = self._duplicate_root()
        file_fd: int | None = None
        try:
            for component in parts[:-1]:
                safe_component = os.path.basename(component)
                if safe_component != component:
                    raise ProjectTreeError("Göreli proje yolu geçersiz bir bileşen içeriyor.")
                next_fd = os.open(safe_component, _DIR_FLAGS, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            safe_leaf = os.path.basename(parts[-1])
            if safe_leaf != parts[-1]:
                raise ProjectTreeError("Göreli proje yolu geçersiz bir bileşen içeriyor.")
            file_fd = os.open(safe_leaf, _FILE_FLAGS, dir_fd=directory_fd)
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode):
                raise ProjectTreeError("Proje girdisi normal bir dosya değil.")
            if expected is not None and _fingerprint(info) != _file_fingerprint(expected):
                raise ProjectTreeError("Proje dosyası yürüyüşten sonra değişti.")
            return file_fd, expected
        except ProjectTreeError:
            if file_fd is not None:
                os.close(file_fd)
            raise
        except OSError as exc:
            if file_fd is not None:
                os.close(file_fd)
            raise ProjectTreeError("Proje dosyası değişti veya sembolik bağ içeriyor.") from exc
        finally:
            os.close(directory_fd)

    def read_bytes(
        self,
        relative: str | os.PathLike[str] | ProjectFile,
        max_bytes: int,
        *,
        allow_empty: bool = False,
        truncate: bool = False,
    ) -> bytes:
        """Read one unchanged regular file through the pinned root descriptor.

        With ``truncate=True``, return at most ``max_bytes`` from an otherwise
        unchanged file.  The default requires the complete file to fit.
        """
        if type(truncate) is not bool:
            raise ProjectTreeError("Dosya kırpma seçeneği geçersiz.")
        limit = _validate_limit(max_bytes, name="Dosya bayt sınırı", upper=MAX_READ_BYTES)
        fd, expected = self._open_file(relative)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ProjectTreeError("Proje girdisi normal bir dosya değil.")
            if expected is not None and _fingerprint(before) != _file_fingerprint(expected):
                raise ProjectTreeError("Proje dosyası yürüyüşten sonra değişti.")
            if not truncate and before.st_size > limit:
                raise ProjectTreeError("Proje dosyası boyut sınırını aşıyor.")
            if before.st_size == 0 and not allow_empty:
                raise ProjectTreeError("Boş proje dosyasına izin verilmedi.")

            chunks: list[bytes] = []
            total = 0
            read_limit = limit if truncate else limit + 1
            while total < read_limit:
                chunk = os.read(fd, min(65_536, read_limit - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            after = os.fstat(fd)
            if not truncate and total > limit:
                raise ProjectTreeError("Proje dosyası okuma sırasında boyut sınırını aştı.")
            if (not truncate and total != before.st_size) or _fingerprint(after) != _fingerprint(before):
                raise ProjectTreeError("Proje dosyası okuma sırasında değişti.")
            if total == 0 and not allow_empty:
                raise ProjectTreeError("Boş proje dosyasına izin verilmedi.")
            return b"".join(chunks)
        except ProjectTreeError:
            raise
        except OSError as exc:
            raise ProjectTreeError("Proje dosyası güvenli biçimde okunamadı.") from exc
        finally:
            os.close(fd)

    def read_text(
        self,
        relative: str | os.PathLike[str] | ProjectFile,
        max_bytes: int,
        *,
        encoding: str = "utf-8",
        errors: str = "strict",
        allow_empty: bool = False,
        truncate: bool = False,
    ) -> str:
        """Read and decode one bounded regular file through the pinned root."""
        return self.read_bytes(
            relative,
            max_bytes,
            allow_empty=allow_empty,
            truncate=truncate,
        ).decode(encoding, errors=errors)

    @staticmethod
    def _skip_names(skip_dirs: Collection[str]) -> frozenset[str]:
        names: set[str] = set()
        for name in skip_dirs:
            if not isinstance(name, str) or name in ("", ".", "..") or "/" in name or "\\" in name or "\x00" in name:
                raise ProjectTreeError("Atlanacak dizin adı geçersiz.")
            names.add(name.casefold())
        return frozenset(names)

    def walk(
        self,
        *,
        skip_dirs: Collection[str] = (),
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_depth: int = DEFAULT_MAX_DEPTH,
        reject_unsafe: bool = True,
    ) -> Iterator[ProjectWalkEntry]:
        """Yield a deterministic recursive walk rooted at the pinned descriptor.

        Every consumed entry must be a regular file or a real directory.
        With ``reject_unsafe=True`` (the default), symlinks, sockets, devices
        and FIFOs fail the whole operation closed.  Project scanners that
        historically ignored such entries can set it to ``False``; unsafe
        entries are then omitted and never opened.
        """
        if type(reject_unsafe) is not bool:
            raise ProjectTreeError("Güvensiz girdi ilkesi geçersiz.")
        entry_limit = _validate_limit(max_entries, name="Ağaç girdi sınırı", upper=10_000_000)
        depth_limit = _validate_limit(max_depth, name="Ağaç derinlik sınırı", upper=1024)
        skipped = self._skip_names(skip_dirs)
        stack: list[tuple[PurePosixPath, int, int]] = [(PurePosixPath("."), self._duplicate_root(), 0)]
        seen = 0
        try:
            while stack:
                relative_dir, directory_fd, depth = stack.pop()
                child_directories: list[tuple[PurePosixPath, os.stat_result]] = []
                skipped_directories: list[PurePosixPath] = []
                files: list[ProjectFile] = []
                try:
                    try:
                        with os.scandir(directory_fd) as entries:
                            for entry in entries:
                                seen += 1
                                if seen > entry_limit:
                                    raise ProjectTreeError("Proje ağacı girdi sınırını aşıyor.")
                                name = entry.name
                                if not isinstance(name, str) or name in ("", ".", "..") or "/" in name or "\x00" in name:
                                    raise ProjectTreeError("Proje ağacı geçersiz bir girdi içeriyor.")
                                info = entry.stat(follow_symlinks=False)
                                path = _join(relative_dir, name)
                                if stat.S_ISLNK(info.st_mode):
                                    if reject_unsafe:
                                        raise ProjectTreeError("Proje ağacı sembolik bağ içeriyor.")
                                    continue
                                if stat.S_ISDIR(info.st_mode):
                                    if name.casefold() in skipped:
                                        skipped_directories.append(path)
                                    else:
                                        if depth >= depth_limit:
                                            raise ProjectTreeError("Proje ağacı derinlik sınırını aşıyor.")
                                        child_directories.append((path, info))
                                    continue
                                if not stat.S_ISREG(info.st_mode):
                                    if reject_unsafe:
                                        raise ProjectTreeError("Proje ağacı normal olmayan bir dosya içeriyor.")
                                    continue
                                files.append(ProjectFile(
                                    path=path,
                                    size=info.st_size,
                                    device=info.st_dev,
                                    inode=info.st_ino,
                                    mtime_ns=info.st_mtime_ns,
                                    ctime_ns=info.st_ctime_ns,
                                ))
                    except ProjectTreeError:
                        raise
                    except OSError as exc:
                        raise ProjectTreeError("Proje dizini güvenli biçimde listelenemedi.") from exc

                    child_directories.sort(key=lambda item: item[0].as_posix())
                    skipped_directories.sort(key=lambda path: path.as_posix())
                    files.sort(key=lambda item: item.path.as_posix())
                    yield ProjectWalkEntry(
                        directory=relative_dir,
                        directories=tuple(path for path, _info in child_directories),
                        files=tuple(files),
                        skipped_directories=tuple(skipped_directories),
                    )

                    opened: list[tuple[PurePosixPath, int, int]] = []
                    try:
                        for child_path, expected in reversed(child_directories):
                            child_fd = os.open(child_path.name, _DIR_FLAGS, dir_fd=directory_fd)
                            opened_info = os.fstat(child_fd)
                            if not stat.S_ISDIR(opened_info.st_mode) or (
                                opened_info.st_dev,
                                opened_info.st_ino,
                            ) != (expected.st_dev, expected.st_ino):
                                os.close(child_fd)
                                raise ProjectTreeError("Proje dizini yürüyüş sırasında değişti.")
                            opened.append((child_path, child_fd, depth + 1))
                    except ProjectTreeError:
                        for _path, child_fd, _depth in opened:
                            os.close(child_fd)
                        raise
                    except OSError as exc:
                        for _path, child_fd, _depth in opened:
                            os.close(child_fd)
                        raise ProjectTreeError("Proje dizini değişti veya sembolik bağ içeriyor.") from exc
                    stack.extend(opened)
                finally:
                    os.close(directory_fd)
        finally:
            for _relative, directory_fd, _depth in stack:
                os.close(directory_fd)

    def iter_files(
        self,
        *,
        skip_dirs: Collection[str] = (),
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_depth: int = DEFAULT_MAX_DEPTH,
        reject_unsafe: bool = True,
    ) -> Iterator[ProjectFile]:
        """Yield regular files discovered by :meth:`walk` in stable order."""
        for directory in self.walk(
            skip_dirs=skip_dirs,
            max_entries=max_entries,
            max_depth=max_depth,
            reject_unsafe=reject_unsafe,
        ):
            yield from directory.files


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_ENTRIES",
    "MAX_READ_BYTES",
    "MAX_RELATIVE_PATH_BYTES",
    "ProjectFile",
    "ProjectTree",
    "ProjectTreeError",
    "ProjectWalkEntry",
]
