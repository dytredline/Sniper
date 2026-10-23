"""Proje düzeyinde Terraform analizi (19. tur): modül (dizin) bağlamı ve yerel modül çağrıları.

* Her dizin bir Terraform modülüdür. ``variable`` varsayılanları, aynı dizindeki ``terraform.tfvars`` ve
  ``*.auto.tfvars`` değerleri ile ``locals`` bir bağlam oluşturur; kaynak öznitelikleri bu bağlamda çözülür
  (``iac_tf_eval``). Değişkenin varsayılanı yoksa değer bilinmiyor sayılır (denetim susar).
* Yerel modül çağrısı (``source = "./modules/x"``, proje kökü dışına çıkmayan göreli yol): çağrıdaki girdiler
  modülün değişkenlerine verilir ve modülün kaynakları o örnek için ayrıca denetlenir. Bulgu modül dosyasının
  satırında, ``module.<ad>.`` önekli kaynak adresiyle raporlanır; kanıta çağrı yeri eklenir. Aynı kural + satır bir
  kez raporlanır (bağımsız modül analizi + örnekler birleştirilir). İç içe modüller en çok ``MAX_MODULE_DEPTH``
  düzey, döngü korumalı.
* Açıkça ``count = 0`` veya boş ``for_each`` yazılan blok örnek üretmez. Değişken varsayılanıyla kapalı görünen
  blok yine denetlenir; değer uygulama anında değiştirilebilir.
* Ayrıştırılamayan dosya için sonuç üretilmez (çağıran eski desen kurallarına düşer).
"""
from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass, field
from typing import Any

import iac_engine
import iac_hcl
import iac_tf_eval
from iac_hcl import Block, Call, Unknown

MAX_MODULE_DEPTH = 4
MAX_INSTANCES = 400  # çok sayıda modül çağrısında üst sınır (süre bütçesi)
MAX_MODULE_OUTPUT_INSTANCES = 64  # count/for_each çıktı şeklini bellek ve değerlendirme açısından sınırlar
_META_ARGS = {"source", "version", "count", "for_each", "providers", "depends_on"}


def _automatic_tfvars(name: str) -> bool:
    return name in ("terraform.tfvars", "terraform.tfvars.json") or \
        name.endswith((".auto.tfvars", ".auto.tfvars.json"))


def _tfvars_precedence(name: str) -> tuple[int, str]:
    if name == "terraform.tfvars":
        return 0, ""
    if name == "terraform.tfvars.json":
        return 1, ""
    return 2, name


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"geçersiz JSON sabiti: {value}")


@dataclass
class _Module:
    dir: str
    roots: dict[str, Block] = field(default_factory=dict)  # tf dosyası → kök
    lines: dict[str, list[str]] = field(default_factory=dict)
    defaults: dict[str, Any] = field(default_factory=dict)
    variable_kinds: dict[str, str] = field(default_factory=dict)
    locals_raw: dict[str, Any] = field(default_factory=dict)
    tfvars: dict[str, Any] = field(default_factory=dict)
    facts: iac_engine.ModuleFacts | None = None


def _dirname(rel: str) -> str:
    return posixpath.dirname(rel)


class TerraformProject:
    """``files``: proje köküne göreli yol → metin (yalnız .tf ve otomatik tfvars biçimleri)."""

    def __init__(self, files: dict[str, str]):
        self.modules: dict[str, _Module] = {}
        self.tfvars_files: dict[str, str] = {}
        self.failed: set[str] = set()
        self.limitations: set[str] = set()
        for rel, text in files.items():
            if _automatic_tfvars(posixpath.basename(rel)):
                self.tfvars_files[rel] = text
                continue
            try:
                root = iac_hcl.parse(text)
            except iac_hcl.HclError as exc:
                self.failed.add(rel)
                if "belirteç sınırı" in str(exc):
                    self.limitations.add("hcl-token")
                continue
            module = self.modules.setdefault(_dirname(rel), _Module(_dirname(rel)))
            module.roots[rel] = root
            module.lines[rel] = text.splitlines()
        for module in self.modules.values():
            for root in module.roots.values():
                for block in root.blocks:
                    if block.type == "variable" and block.labels:
                        declared_type = block.attrs.get("type")
                        if declared_type is not None and isinstance(declared_type.value, Call) and \
                                declared_type.value.name in {"list", "map", "set"}:
                            module.variable_kinds[block.labels[0]] = declared_type.value.name
                        default = block.attrs.get("default")
                        module.defaults[block.labels[0]] = default.value if default is not None \
                            else Unknown(f"var.{block.labels[0]}")
                    elif block.type == "locals":
                        for name, attr in block.attrs.items():
                            module.locals_raw[name] = attr.value
            module.facts = iac_engine.module_facts(module.roots.values())
        # Kök modül değerleri: aynı dizindeki HCL/JSON otomatik tfvars dosyaları. Terraform önce sabit adlı
        # HCL, sonra JSON dosyasını; ardından iki auto uzantısını ortak dosya adı sırasıyla yükler.
        # Çağıranın sözlük ekleme sırası veya os.walk sırası değerlendirme sonucunu değiştirmemeli.
        ordered_tfvars = sorted(
            self.tfvars_files.items(),
            key=lambda item: (
                _dirname(item[0]),
                *_tfvars_precedence(posixpath.basename(item[0])),
            ),
        )
        for rel, text in ordered_tfvars:
            name = posixpath.basename(rel)
            if not _automatic_tfvars(name):
                continue
            module = self.modules.get(_dirname(rel))
            if module is None:
                continue
            if name.endswith(".json"):
                try:
                    values = json.loads(text, parse_constant=_reject_json_constant)
                except (ValueError, RecursionError):
                    continue
                if not isinstance(values, dict):
                    continue
                module.tfvars.update(values)
                continue
            try:
                root = iac_hcl.parse(text)
            except iac_hcl.HclError:
                continue
            for key, attr in root.attrs.items():
                if not iac_hcl.is_unknown(attr.value):
                    module.tfvars[key] = attr.value

    # -- bağlam ----------------------------------------------------------------------------------------
    def _ctx(self, module: _Module, inputs: dict[str, Any] | None = None) -> iac_tf_eval.Ctx:
        variables: dict[str, Any] = {}
        base = iac_tf_eval.Ctx({}, {})
        for name, default in module.defaults.items():
            variables[name] = iac_tf_eval.resolve(default, base)
        if inputs is None:
            variables.update(module.tfvars)
        else:
            variables.update(inputs)
        return iac_tf_eval.Ctx(variables, dict(module.locals_raw))

    def _local_source(self, caller_dir: str, block: Block) -> str | None:
        source = block.attrs.get("source")
        if source is None or not isinstance(source.value, str):
            return None
        value = source.value.strip()
        if not value.startswith(("./", "../")):
            return None
        target = posixpath.normpath(posixpath.join(caller_dir or ".", value))
        if target.startswith("..") or posixpath.isabs(target):
            return None  # proje kökü dışına çıkılmaz
        target = "" if target == "." else target
        return target if target in self.modules else None

    # -- analiz -----------------------------------------------------------------------------------------
    def analyze(self) -> iac_engine.ProjectResults:
        """Dosya → sonuç. Ayrıştırılamayan dosyalar sonuçta yer almaz."""
        merged = iac_engine.ProjectResults()
        seen: dict[str, set[tuple[str, int]]] = {}
        analysis_instances = [0]
        output_instances = [0]

        def add_results(results: dict[str, iac_engine.IacResult], note: str = "") -> None:
            for rel, result in results.items():
                target = merged.setdefault(rel, iac_engine.IacResult("terraform"))
                keys = seen.setdefault(rel, set())
                target.resources = max(target.resources, result.resources)
                for item in result.findings:
                    key = (item["id"], item["line"])
                    if key in keys:
                        continue
                    keys.add(key)
                    if note:
                        item = dict(item, evidence=f"{item['evidence']} {note}")
                    target.findings.append(item)

        def prepare_outputs(module: _Module, ctx: iac_tf_eval.Ctx, stack: tuple[str, ...]) -> \
                dict[str, tuple[str, Block, str, iac_tf_eval.Ctx]]:
            local_calls: dict[str, tuple[str, Block, str, iac_tf_eval.Ctx]] = {}
            if len(stack) >= MAX_MODULE_DEPTH:
                # Derinlik sınırına gelmek tek başına kayıp değildir: yaprak modül tamdır. Yalnız
                # gerçekten izlenemeyen, döngü olmayan bir yerel çağrı varsa sonucu kısmi işaretle.
                for root in module.roots.values():
                    for raw in root.blocks:
                        if raw.type == "module" and raw.labels and not iac_engine._disabled(raw):
                            target = self._local_source(module.dir, raw)
                            if target is not None and target not in stack:
                                self.limitations.add("module-depth")
                                return local_calls
                return local_calls
            # Terraform bildirim sırası anlam taşımaz. Bir modül girdisi aynı dizindeki daha sonra bildirilen
            # başka bir modülün çıktısını kullanabilir. Ham ifadelerdeki module.x ve bunlara aracılık eden
            # local.x başvurularını bulup üreticiyi tüketiciden önce hazırla; döngüde değer bilinmeyen kalır.
            calls: dict[str, tuple[str, Block]] = {}
            order: list[str] = []
            for rel, root in module.roots.items():
                for raw in root.blocks:
                    if raw.type == "module" and raw.labels and not iac_engine._disabled(raw) and \
                            raw.labels[0] not in calls:
                        calls[raw.labels[0]] = (rel, raw)
                        order.append(raw.labels[0])

            def refs(value: Any, local_stack: set[str] | None = None, depth: int = 0) -> set[str]:
                found: set[str] = set()
                if depth > iac_tf_eval.MAX_DEPTH:
                    return found
                if isinstance(value, Unknown):
                    toks = list(value.toks)
                    for index in range(len(toks) - 2):
                        head, dot, name = toks[index:index + 3]
                        if head.kind != "id" or dot.kind != "p" or dot.value != "." or name.kind != "id":
                            continue
                        if head.value == "module":
                            found.add(str(name.value))
                        elif head.value == "local" and name.value in module.locals_raw:
                            seen = set(local_stack or ())
                            local_name = str(name.value)
                            if local_name not in seen:
                                seen.add(local_name)
                                found.update(refs(module.locals_raw[local_name], seen, depth + 1))
                elif isinstance(value, Call):
                    for argument in value.args:
                        found.update(refs(argument, local_stack, depth + 1))
                elif isinstance(value, list):
                    for item in value:
                        found.update(refs(item, local_stack, depth + 1))
                elif isinstance(value, dict):
                    for item in value.values():
                        found.update(refs(item, local_stack, depth + 1))
                return found

            prepared: set[str] = set()
            active_calls: set[str] = set()

            def collection_kind(value: Any, seen_locals: frozenset[str] = frozenset(), depth: int = 0) -> \
                    str | None:
                """Ham HCL ifadesindeki açık koleksiyon türünü, kod çalıştırmadan izler."""
                if depth > iac_tf_eval.MAX_DEPTH:
                    return None
                if isinstance(value, dict):
                    return "map"
                if isinstance(value, list):
                    return "list"
                if isinstance(value, Call):
                    return {
                        "map": "map",
                        "tomap": "map",
                        "set": "set",
                        "toset": "set",
                        "list": "list",
                        "tolist": "list",
                        "tuple": "list",
                    }.get(value.name)
                if not isinstance(value, Unknown):
                    return None
                toks = [tok for tok in value.toks if tok.kind not in {"nl", "eof"}]
                if len(toks) != 3 or toks[0].kind != "id" or toks[1].kind != "p" or \
                        toks[1].value != "." or toks[2].kind != "id":
                    return None
                namespace = str(toks[0].value)
                name = str(toks[2].value)
                if namespace == "var":
                    return module.variable_kinds.get(name)
                if namespace != "local" or name in seen_locals or name not in module.locals_raw:
                    return None
                return collection_kind(module.locals_raw[name], seen_locals | {name}, depth + 1)

            def output_shape(call: Block, raw_call: Block, outputs: dict[str, Any]) -> Any:
                """Terraform'in statik modül örnek adreslemesini sınırlı bir değer şekline dönüştür."""
                count = call.attrs.get("count")
                for_each = call.attrs.get("for_each")
                if count is not None:
                    value = count.value
                    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= \
                            MAX_MODULE_OUTPUT_INSTANCES:
                        return [dict(outputs) for _ in range(value)]
                    if isinstance(value, (int, float)) and not isinstance(value, bool) and \
                            value > MAX_MODULE_OUTPUT_INSTANCES:
                        self.limitations.add("module-output-instances")
                    return Unknown(f"module.{call.labels[0]}[count]")
                if for_each is not None:
                    value = for_each.value
                    raw_for_each = raw_call.attrs.get("for_each")
                    raw_value = raw_for_each.value if raw_for_each is not None else None
                    if isinstance(value, dict):
                        keys = [key for key in value if isinstance(key, str)]
                        if len(keys) == len(value) and len(keys) <= MAX_MODULE_OUTPUT_INSTANCES:
                            return {key: dict(outputs) for key in keys}
                        if len(value) > MAX_MODULE_OUTPUT_INSTANCES:
                            self.limitations.add("module-output-instances")
                        return Unknown(f"module.{call.labels[0]}[for_each]")
                    # Terraform for_each çıplak liste/toList kabul etmez; yalnız küme veya map gerekir.
                    # Hafif değerlendirici kümeyi listeye indirgediği için ham ifade ve açık değişken türü
                    # üzerinden, sınırlı local zincirini de izleyerek koleksiyon türünü koruruz.
                    if isinstance(value, list) and collection_kind(raw_value) == "set" and \
                            all(isinstance(item, str) for item in value):
                        keys = list(dict.fromkeys(value))
                        if len(keys) <= MAX_MODULE_OUTPUT_INSTANCES:
                            return {key: dict(outputs) for key in keys}
                        self.limitations.add("module-output-instances")
                    return Unknown(f"module.{call.labels[0]}[for_each]")
                return outputs

            def prepare_call(name: str) -> None:
                if name in prepared or name in active_calls or name not in calls:
                    return
                active_calls.add(name)
                rel, raw = calls[name]
                dependencies: set[str] = set()
                for attr in raw.attrs.values():
                    dependencies.update(refs(attr.value))
                for dependency in sorted(dependencies):
                    prepare_call(dependency)
                # Bir local ilk erişimde bilinmeyen modül çıktısıyla önbelleğe alınmış olabilir.
                ctx._locals.clear()
                resolved_call = iac_tf_eval.resolve_block(raw, ctx)
                target = self._local_source(module.dir, resolved_call)
                if target is not None and target not in stack:
                    if output_instances[0] >= MAX_INSTANCES:
                        self.limitations.add("module-instances")
                    else:
                        output_instances[0] += 1
                        child = self.modules[target]
                        inputs = {k: a.value for k, a in resolved_call.attrs.items() if k not in _META_ARGS}
                        child_ctx = self._ctx(child, inputs)
                        prepare_outputs(child, child_ctx, stack + (target,))
                        outputs: dict[str, Any] = {}
                        for child_root in child.roots.values():
                            for output in child_root.blocks:
                                if output.type == "output" and output.labels and "value" in output.attrs:
                                    outputs[output.labels[0]] = iac_tf_eval.resolve(
                                        output.attrs["value"].value, child_ctx)
                        ctx.modules[name] = output_shape(resolved_call, raw, outputs)
                        ctx._locals.clear()
                        local_calls[name] = (target, resolved_call, rel, child_ctx)
                active_calls.discard(name)
                prepared.add(name)

            for name in order:
                prepare_call(name)
            return local_calls

        def run_module(module: _Module, ctx: iac_tf_eval.Ctx, prefix: str, stack: tuple[str, ...]) -> \
                dict[str, iac_engine.IacResult]:
            # Çıktı hazırlığı analiz sonucu eklemez; böylece bir modül yalnız aşağıdaki normal
            # geçişte ve doğru çağrı kanıtıyla raporlanır.
            local_calls = prepare_outputs(module, ctx, stack)
            results: dict[str, iac_engine.IacResult] = {}
            resolved_roots: dict[str, Block] = {}
            for rel, root in module.roots.items():
                resolved = iac_tf_eval.resolve_block(root, ctx)
                resolved_roots[rel] = resolved
                for block in resolved.blocks:
                    if block.type == "module" and block.labels:
                        target = self._local_source(module.dir, block)
                        # Bütçe/döngü nedeniyle hazırlanamayan yerel çağrı bilinmeyen kalır ve izlenmez.
            # Yerel modül çağrısındaki girdiler (ör. storage_encrypted = false) çağrı satırında da denetlenir: değeri
            # veren satır orasıdır; modülün kaynağı ayrıca örnek bağlamında denetlenir.
            for rel, resolved in resolved_roots.items():
                results[rel] = iac_engine.analyze_terraform_root(
                    resolved, module.lines[rel], original=module.roots[rel], facts=module.facts,
                    prefix=prefix, resolved=True)
            if len(stack) >= MAX_MODULE_DEPTH:
                return results
            for call_name, (target, block, rel, child_ctx) in local_calls.items():
                if target in stack:
                    continue
                if analysis_instances[0] >= MAX_INSTANCES:
                    self.limitations.add("module-instances")
                    continue
                analysis_instances[0] += 1
                child = self.modules[target]
                note = f"(modül çağrısı: {rel}:{block.line}, module.{call_name})"
                add_results(run_module(child, child_ctx, f"{prefix}module.{call_name}.", stack + (target,)), note)
            return results

        # Her modül kendi bağlamında (kök modül tfvars ile); çağrı örnekleri run_module içinde özyinelemeli.
        for module in self.modules.values():
            add_results(run_module(module, self._ctx(module), "", (module.dir,)))
        if self.limitations:
            merged.mark_incomplete(*sorted(self.limitations))
        return merged


def analyze_files(files: dict[str, str]) -> iac_engine.ProjectResults:
    """Kolaylık: Terraform dosyalarını proje bağlamında analiz et."""
    return TerraformProject(files).analyze()


MAX_TF_FILES = 3000
MAX_TF_FILE_BYTES = 1_000_000
MAX_TF_TOTAL_BYTES = 30_000_000


def scan_tree(root, skip_dirs) -> iac_engine.ProjectResults:
    """Proje kökündeki .tf dosyalarını (atlanan dizinler, sembolik bağlar ve boyut sınırlarıyla) toplayıp proje
    bağlamında analiz eder. project_analyzer dosya döngüsü her .tf dosyası için bu sonuçtan okur."""
    import os
    import stat
    from pathlib import Path

    root = Path(root)
    files: dict[str, str] = {}
    total = 0
    limitations: set[str] = set()
    for current, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(d for d in directories
                                if d.casefold() not in skip_dirs and d != ".terraform"
                                and not (Path(current) / d).is_symlink())
        for name in sorted(names):
            # Terraform yalnız sabit adlı ve *.auto adlı HCL/JSON tfvars dosyalarını otomatik yükler. Bu girdiler
            # değerlendirme katmanında zaten destekleniyordu ancak proje yürüyüşü onları hiç toplamıyordu.
            # Aynı dosya/bayt bütçesini tüketmeleri, çok sayıda tfvars ile sınırın aşılmasını engeller.
            automatic_tfvars = _automatic_tfvars(name)
            if not (name.endswith(".tf") or automatic_tfvars):
                continue
            path = Path(current) / name
            try:
                info = os.stat(path, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_size > MAX_TF_FILE_BYTES:
                limitations.add("file-bytes")
                continue
            if len(files) >= MAX_TF_FILES or total + info.st_size > MAX_TF_TOTAL_BYTES:
                limitations.add("file" if len(files) >= MAX_TF_FILES else "total-bytes")
                result = TerraformProject(files).analyze()
                return result.mark_incomplete(*sorted(limitations))
            try:
                files[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            total += info.st_size
    result = TerraformProject(files).analyze()
    return result.mark_incomplete(*sorted(limitations)) if limitations else result
