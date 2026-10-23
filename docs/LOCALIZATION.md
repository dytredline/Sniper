# Sniper Community localization

Sniper Community 1.0 arayüz ve HTML raporlarında Türkçe (`tr`) kaynak dili ile İngilizce (`en`) temel
paketi; Japonca (`ja`), Basitleştirilmiş Çince (`zh-CN`) ve Korece (`ko`) genişletilmiş başlangıç
paketleri sunar. İngilizce görünür-arayüz sözlüğü mevcut kapsam testinde 1908/2064 (%92,4) dizgeyi
kapsar; bu nedenle tam çeviri iddiası yoktur. Seçili CJK paketinde bulunmayan metin, İngilizce girdisi
varsa İngilizceye düşer; İngilizce girdisi de yoksa özgün Türkçe kaynak korunur. Kaynak kod, dosya
yolları, komutlar ve bulgu kanıtı gibi kullanıcı verileri çeviri katmanına sokulmaz.

| Paket | Bu adayda doğrulanan kapsam |
| --- | --- |
| İngilizce | 1908/2064 görünür arayüz dizgesi (%92,4) |
| Japonca | 306 yüksek değerli sabit/kalıp girdisi |
| Basitleştirilmiş Çince | 353 yüksek değerli sabit/kalıp girdisi |
| Korece | 303 yüksek değerli sabit/kalıp girdisi |

Türkçe biçimlenmiş tarihler İngilizcede İngilizce ay kısaltmasına; Japonca, Çince ve Korecede seçili
dilin yıl/ay/gün düzenine çevrilir. Paket sayıları ürünün tüm olası dinamik metinlerinin çevrildiği anlamına gelmez.

## Dil paketi sözleşmesi

Her paket `static/i18n-<locale>.tsv` yolundadır. İlk satır `# sniper-i18n/1<TAB><locale>` biçimindedir.
`S` tam metin, `P` `{0}` gibi yer tutuculu kalıp, `F` ise kontrollü kanıt parçası kaydıdır. Bir `P`
kaydının kaynak ve hedef tarafında aynı yer tutucular bulunmalıdır. Değerler HTML içeremez; arayüz bunları
yalnız `nodeValue` ve güvenli öznitelik yazımıyla uygular.

Yeni bir dil eklerken:

1. TSV paketini ekleyin ve `i18n_server.DICTIONARY_PATHS` ile `static/i18n.js` dil kaydına bağlayın.
2. `static/index.html` ve `static/login.html` seçicilerine yerel dil adını ekleyin.
3. Giriş öncesi kullanım için paketi `auth_routes.LOGIN_ASSETS` listesine alın.
4. Sunucu, DOM ve gerçek tarayıcı sözleşmelerine yeni dili ekleyin.
5. Yer tutucuları, HTML içermeme kuralını, masaüstü/mobil taşmayı ve rapor `lang` değerini doğrulayın.

Bu değişiklikler motor veya veri şeması değişmeden bağımsız bir çeviri güncellemesi olarak yayımlanabilir.
Semantik sürümlemede yalnız çeviri düzeltmesi yama sürümü; yeni bir dil veya belirgin kapsam genişlemesi küçük
sürüm olarak işaretlenebilir. Yayın yine tam regresyon ve Community kaynak ağacı doğrulamasından geçer.

## Mevcut doğrulama

- `tests/test_i18n_server.py`: İngilizce temel paket, rapor ve sözlük sözleşmesi.
- `tests/test_i18n_multilingual.py`: ja/zh-CN/ko sunucu paketleri, takma adlar ve giriş kapısı varlıkları.
- `tests/test_i18n_ui.mjs`: dil geçişi, İngilizce fallback, güvenli DOM yazımı ve dinamik içerik.
- `tests/test_i18n_layout_contract.mjs`: seçici ve CJK taşma CSS sözleşmesi.
- `browser-tests/test_i18n_layout_browser.mjs`: pinli Chromium ile beş dilde masaüstü ve mobil gerçek düzen testi.
