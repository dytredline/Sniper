# Sniper editör tanılama sunucusu (LSP)

`scripts/sniper-lsp`, stdio üzerinden konuşan bir Language Server Protocol sunucusudur (saf Python, yalnız standart
kitaplık). Editörde bir dosya **açıldığında ya da kaydedildiğinde** o dosya, arayüzdeki proje analiziyle aynı motorla
incelenir ve bulgular editörde tanılama (altı çizili uyarı) olarak görünür. Desteklenen dosyalar için hızlı düzeltme
(Quick Fix) önerilir.

## Ne yapar

| LSP iletisi | Davranış |
|---|---|
| `initialize` | Çalışma alanı kökü(leri) `workspaceFolders` / `rootUri` ile alınır. |
| `textDocument/didOpen`, `didSave` | Dosya proje bağlamıyla analiz edilir, `publishDiagnostics` gönderilir. |
| `textDocument/didChange` | Yalnız bellekteki metin güncellenir (tam eşitleme). Analiz kayıtta yapılır. |
| `textDocument/didClose` | Dosyanın tanılamaları temizlenir. |
| `textDocument/codeAction` | Sniper tanılaması için `taint_autofix` dönüşümü (parametreli sorgu, kabuksuz komut, kaçış …) **quickfix** düzenlemesi olarak önerilir; editörün kaydedilmemiş metni üzerinde hesaplanır. Düzenlemeyi editör uygular, sunucu dosyaya yazmaz. |
| `shutdown` / `exit` | Standart yaşam döngüsü. |

Tanılama içeriği:

* **Önem:** kritik/yüksek → hata, orta → uyarı, düşük → bilgi, bilgi → ipucu.
* **Kod:** CWE (bağlantılı) ya da IaC kontrol kimliği.
* **İleti:** başlık, kanıt ve öneri.
* **İlgili konum:** veri akışlarında kaynağın dosyası ve satırı.
* `data.fingerprint`: arayüzdeki **bulgu takibi** ile aynı parmak izi (satırdan bağımsız). Editördeki bulgu,
  takip ekranındaki kayıtla bu değerle eşleştirilebilir.

## Kapsam, hız ve önbellek

* Analiz, `project_analyzer` ile yalnız açılan dosya raporlanacak biçimde yapılır (`only_paths`). Dosyalar arası
  veri akışı bağlamı tüm projeden gelir.
* **Kalıcı tarama kapsamı** (`$SNIPER_DATA_DIR/scan-scope.json`) okunur, yazılmaz. Varsayılan kapsamda test/vendor
  dizinleri ve 1 MB'den büyük dosyalar atlanır; arayüzde kapsamı genişletirseniz editör de onu izler.
* **Süre sınırı:** Her analiz ayrı bir alt süreçte, dosya başına süre sınırıyla (varsayılan 30 sn) çalışır. Süre
  aşılırsa süreç grubu sonlandırılır, önceki tanılamalar korunur, editöre bir günlük iletisi düşer.
* **Önbellek:**
  * Yeniden açılan, değişmemiş dosya bellekteki sonuçtan anında döner.
  * Python projelerinde dosyalar arası taint sonucu `~/.cache/sniper-lsp/taint-cache` altında diskte tutulur
    (dizin 0700); proje değişmediyse yeniden hesaplanmaz.
  * Kaydedilen dosya değiştiyse proje bağlamı yeniden kurulur.
  * Ölçüm (bu makinede):

    | Proje | İlk açılış | Yeniden açma | İçerik değişmeden kayıt | Not |
    |---|---|---|---|---|
    | django | 4,4 sn | 0 sn | 0,5 sn | |
    | juice-shop (TS) | 7,5 sn | 0 sn | 7,5 sn | JS için disk önbelleği yok |
    | pygoat | 0,3 sn | 0 sn | 0,2 sn | |

* **Ağ ve yazma:** Ağ erişimi yoktur. Proje dosyalarına ve Sniper'ın canlı veri dizinine hiçbir şey yazılmaz.

## Kurulum

Sunucu Sniper uygulama dizinindedir:

```
~/.local/share/sniper/app/scripts/sniper-lsp [--data-dir DİZİN] [--cache-dir DİZİN] [--timeout SN]
```

Seçenekler:

* `--data-dir`: Sniper veri dizini; yalnız kalıcı tarama kapsamı okunur. Varsayılan `$SNIPER_DATA_DIR` ya da
  `~/.local/share/sniper/data`.
* `--cache-dir`: varsayılan `~/.cache/sniper-lsp`.
* `--timeout`: dosya başına süre sınırı, 2–300 sn.

İstemci `initializationOptions` ile de ayar verebilir:

```json
{ "timeoutSeconds": 45, "minSeverity": "medium", "dataDir": "~/.local/share/sniper/data" }
```

`minSeverity`: `info` | `low` | `medium` | `high` | `critical`; altındaki bulgular gösterilmez.

Proje klasörü, arayüzdeki analizle aynı kurala uyar: kullanıcı dizini ya da bağlı yerel disk altında olmalıdır.

### Neovim 0.11+ (yerleşik `vim.lsp.config`)

```lua
vim.lsp.config('sniper', {
  cmd = { vim.fn.expand('~/.local/share/sniper/app/scripts/sniper-lsp') },
  filetypes = { 'python', 'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
                'go', 'ruby', 'java', 'kotlin', 'cs', 'php', 'rust', 'c', 'cpp',
                'terraform', 'yaml', 'dockerfile' },
  root_markers = { '.git' },
  init_options = { timeoutSeconds = 30, minSeverity = 'low' },
})
vim.lsp.enable('sniper')
```

Hızlı düzeltme: imleç bulgu satırındayken `vim.lsp.buf.code_action()`.

### Neovim (nvim-lspconfig, özel sunucu tanımı)

```lua
local configs = require('lspconfig.configs')
local util = require('lspconfig.util')
if not configs.sniper then
  configs.sniper = {
    default_config = {
      cmd = { vim.fn.expand('~/.local/share/sniper/app/scripts/sniper-lsp') },
      filetypes = { 'python', 'javascript', 'typescript', 'go', 'java', 'kotlin', 'cs', 'php', 'ruby', 'rust', 'c', 'cpp' },
      root_dir = util.root_pattern('.git'),
      init_options = { minSeverity = 'low' },
    },
  }
end
require('lspconfig').sniper.setup({})
```

### VS Code

VS Code'da yerleşik "herhangi bir LSP sunucusunu çalıştır" ayarı yoktur. İki yol var:

1. **Genel LSP istemci uzantısı:** Pazar yerinde "generic LSP client" türü uzantılar komut + argüman + dil
   listesiyle bir sunucu başlatabilir. Komut olarak `~/.local/share/sniper/app/scripts/sniper-lsp` verin. Ayar
   adları uzantıya göre değişir; uzantının belgesine bakın.
2. **Birkaç satırlık yerel uzantı** (`vscode-languageclient` ile; kendi makinenizde `code --install-extension`
   ile paketleyip kurabilirsiniz):

```js
// extension.js
const { LanguageClient } = require('vscode-languageclient/node');
const os = require('os');
let client;
exports.activate = () => {
  client = new LanguageClient('sniper', 'Sniper',
    { command: `${os.homedir()}/.local/share/sniper/app/scripts/sniper-lsp`, args: [] },
    { documentSelector: [{ scheme: 'file' }], initializationOptions: { minSeverity: 'low' } });
  client.start();
};
exports.deactivate = () => client && client.stop();
```

## Sınırlar

* Analiz kayıtta yapılır; kaydedilmemiş değişiklikler tanılamaya yansımaz. Hızlı düzeltme ise kaydedilmemiş metin
  üzerinde hesaplanır.
* Yetki envanteri, tehdit modeli gibi proje geneli bulgular ("Proje geneli") editörde gösterilmez; yalnız açık
  dosyaya ait bulgular gösterilir.
* Hızlı düzeltme Python ve JS/TS dönüşümleriyle sınırlıdır; diğer dillerde yalnız tanılama vardır.
* JS/TS projelerinde her kayıtta proje bağlamı yeniden kurulur (büyük projelerde birkaç saniye).
