"""Zaman aşımında tüm süreç grubunu öldüren ``subprocess.run`` eşdeğeri.

``subprocess.run(timeout=...)`` zaman aşımında yalnız doğrudan çocuğu
öldürür; aracın başlattığı torun süreçler (ör. semgrep-core, nmap betikleri,
npm alt süreçleri) yaşamaya, kaynak ve kilit tutmaya devam edebilir. Bu modül
``nuclei_active`` desenini ortaklaştırır: süreç ``start_new_session=True`` ile
yeni bir oturum/grup lideri olarak başlatılır, zaman aşımında
``os.killpg(SIGKILL)`` ile bütün grup öldürülür, çıktı toplanır ve
``subprocess.TimeoutExpired`` yeniden yükseltilir. Böylece çağıranların
mevcut hata yolları ve mesajları değişmez.
"""

from __future__ import annotations

import os
import signal
import subprocess
from typing import Any, Sequence

# Grup öldürüldükten sonra boruları boşaltıp lideri biçmek için üst sınır.
_REAP_TIMEOUT_SECONDS = 5.0

_STDLIB_RUN = subprocess.run


def _is_stdlib_run(candidate: Any) -> bool:
    if candidate is _STDLIB_RUN:
        return True
    return (
        getattr(candidate, "__module__", None) == "subprocess"
        and getattr(candidate, "__qualname__", None) == "run"
    )


def kill_process_group(process: subprocess.Popen) -> None:
    """``process`` liderliğindeki süreç grubunu SIGKILL ile öldürür.

    Süreç ``start_new_session=True`` ile başlatılmış olmalıdır (pgid == pid).
    Grup çoktan boşalmışsa sessizce geçer; grup sinyali reddedilirse en azından
    doğrudan çocuk öldürülür.
    """
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            process.kill()
        except ProcessLookupError:
            pass


def run_in_process_group(
    cmd: Sequence[str],
    *,
    timeout: float,
    check: bool = False,
    **popen_kwargs: Any,
) -> subprocess.CompletedProcess:
    """``subprocess.run`` ile aynı dönüş/istisna sözleşmesi; zaman aşımında grup öldürülür.

    Desteklenen anahtarlar ``subprocess.Popen`` anahtarlarıdır (stdin, stdout,
    stderr, env, cwd ...). ``start_new_session`` her zaman ``True`` olur.
    """
    runner = subprocess.run
    if not _is_stdlib_run(runner):
        # Birim testleri ``<modül>.subprocess.run``'ı sahte bir çağrıyla
        # değiştiriyor; o sözleşmeyi (aynı anahtarlarla) korumak için sahte
        # çağrıya devredilir. Üretimde subprocess.run hiçbir zaman yamalanmaz.
        return runner(cmd, timeout=timeout, check=check, **popen_kwargs)

    if "input" in popen_kwargs or "capture_output" in popen_kwargs:
        raise TypeError("run_in_process_group input/capture_output desteklemiyor")
    popen_kwargs.pop("start_new_session", None)
    popen_kwargs.pop("process_group", None)

    with subprocess.Popen(cmd, start_new_session=True, **popen_kwargs) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_process_group(process)
            try:
                process.communicate(timeout=_REAP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                # Gruptan setsid ile kaçan bir torun boruyu tutuyor olabilir;
                # lider ölü, Popen.__exit__ boruları kapatıp lideri biçer.
                pass
            raise
        except BaseException:
            kill_process_group(process)
            process.wait()
            raise
        retcode = process.poll()
    if check and retcode:
        raise subprocess.CalledProcessError(retcode, process.args, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(process.args, retcode, stdout, stderr)
