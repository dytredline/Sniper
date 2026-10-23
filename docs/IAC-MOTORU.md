# Yerleşik IaC motoru (17. tur)

Trivy/Checkov kurulu olmadan proje analizinde çalışan altyapı-kod denetimi. Ağ yok, dosya çalıştırılmaz.

| Çerçeve | Dosyalar | Denetim |
|---|---|---|
| Terraform | `*.tf`, `terraform.tfvars[.json]`, `*.auto.tfvars[.json]`, bilinen `terraform-aws-modules/*` modül girdileri | güvenlik grubu/güvenlik duvarı (AWS normal/default security group, ayrı ve satır içi `aws_network_acl`/`aws_default_network_acl` genel hassas ingress kuralları; GCP klasik firewall ile hiyerarşik/ağ firewall policy rule; Azure NSG; DigitalOcean firewall, `all` port aralığı dahil; Linode firewall; Vultr firewall rule; Hetzner Cloud `hcloud_firewall`, `any` veya TCP/UDP için atlanmış tüm-port değeri dahil; OpenStack `openstack_networking_secgroup_rule_v2`; OCI `oci_core_security_list` ve `oci_core_network_security_group_security_rule`; Alibaba Cloud `alicloud_security_group_rule`; Huawei Cloud `huaweicloud_networking_secgroup_rule`; virgülle ayrılmış portlar ve iki noktalı port aralıkları; GCP ingress kaynakları ve kaynak etiketleri/hesapları yoksa dünya varsayılanı, `disabled = true` kaynakları dışlanır), genel depolama, şifreleme, IMDSv2, herkese açık veritabanı, IAM `*`, `Principal *` kaynak politikası, KMS döndürme, CloudFront HTTP, eski TLS, SSL'siz veritabanı, CloudTrail, EKS/GKE/AKS, Lambda URL, seri konsol, sabit sır (`AKIA…` dahil) |
| Kubernetes | `apiVersion` + `kind` taşıyan YAML (çok belgeli, `List`), Helm şablonları (kısmi) | privileged, allowPrivilegeEscalation, hostNetwork/PID/IPC, hostPath (docker.sock, hassas dizin), tehlikeli yetenekler, root UID, seccomp/AppArmor unconfined, sabitlenmemiş imaj, ortamda sabit sır, sertleştirme eksikleri (tek bulgu), RBAC joker, cluster-admin bağlama; proje genelinde Ingress, doğrudan NodePort/LoadBalancer, genel `externalIPs` taşıyan Service veya dinleyicisi `allowedRoutes.namespaces.from: Same/All/Selector` ilkesine uyan Gateway API HTTPRoute/GRPCRoute/TCPRoute/TLSRoute/UDPRoute→Service→Workload→ServiceAccount→Role ilişkisi; yalnız özel/loopback/link-local `loadBalancerSourceRanges` ile sınırlandırılmış LoadBalancer internet açıklığı sayılmaz; route türü dinleyici protokolüyle eşleştirilir, `Selector` statik Namespace etiketleriyle ve başka namespace'teki Service hedef Namespace içindeki route türüne özgü `ReferenceGrant` ile doğrulanır |
| Dockerfile | `Dockerfile*`, `Containerfile*` | sabitlenmemiş taban imajı, `curl \| sh`, root kullanıcı, `ADD` uzak adres, sudo, ENV/ARG sır, `chmod 777`, TLS/imza doğrulaması kapatma, `EXPOSE 22`, HEALTHCHECK (bilgi) |
| docker-compose | `services:` içeren YAML | privileged, network/pid/ipc host, docker.sock, cap_add, seccomp/apparmor unconfined, ortamda sır, sabitlenmemiş imaj, root kullanıcı |
| CI/CD | `.github/workflows/*.yml`, `.gitlab-ci.yml` | güvenilmeyen olay verisinin iş kapsamlı GitHub `GITHUB_ENV` ile sonraki adıma, tek veya çok satırlı step output ve açık `needs` bağıyla job output üzerinden sonraki run komutuna ya da GitLab dotenv ile sonraki run/script komutuna taşınması |

GitHub akışı workflow içindeki `run` adımlarını inceler. `uses:` ile çağrılan üçüncü taraf action çıktıları,
proje bağlamında doğrulanmış yerel action sözleşmesi bu katmana verilmediği için güvenli ya da kirli varsayılmaz.

İlkeler:
- Yalnız açıkça yazılmış güvensiz değer raporlanır; değişken, başvuru, `${…}` ve Helm `{{ }}` değerlerinde susulur.
  Varsayılanı güvensiz olup hiç yazılmamış ayar yalnız üç yerde raporlanır (RDS şifreleme, EC2 `metadata_options`,
  KMS döndürme) ve modül çağrılarında uygulanmaz.
- Kubernetes sertleştirme eksikleri iş yükü başına tek düşük önemli bulgudur; Helm şablonu ve imajsız (kustomize yama)
  belgelerde üretilmez.
- Gateway API HTTPRoute, GRPCRoute, TCPRoute, TLSRoute ve UDPRoute ilişkilerinde `Same`, `All` ve `Selector` dinleyici ad alanı ilkeleri,
  `allowedRoutes.kinds`, bölüm ve port birlikte uygulanır.
  `Selector`, aynı manifest kümesindeki tekil ve geçerli `v1/Namespace` etiketlerinde `matchLabels` ile
  `In/NotIn/Exists/DoesNotExist` ifadelerini değerlendirir; Namespace belgesi yoksa ya da yinelenmişse kapalı kalır. Başka
  namespace'teki Service yalnız hedef namespace'te kaynak route türü ile namespace'ini ve hedef Service'i kapsayan
  `gateway.networking.k8s.io/v1beta1` `ReferenceGrant` ile bağlanır; adsız `to` kaydı tüm Service'leri kapsar.
  Helm ile dinamik üretilen ve statik Namespace etiketi kanıtı bulunmayan `Selector` bağları kurulmaz.
- Ayrıştırılamayan dosyada eski desen kuralları devreye girer (gerileme yok). PyYAML yoksa YAML aynı şekilde eski kurallara düşer.
- Her bulgu `iac` alanında motor kontrol kimliği (`SNP-IAC-…`), kaynak adresi ve Checkov eşdeğerlerini taşır.
- Kural meta verisi `rules/iac/*.json`; basit Terraform denetimleri orada bildirimsel `match` olarak tanımlanır.

Ölçüm (geliştirme sırasında; KICS sorgu testleri ayar için kullanıldı): eşlenen 85 sorguda pozitif dosyaların %76'sı,
negatif dosyaların %7,6'sında ilgili kural tetiklendi — negatif isabetlerin tamamı motorun daha geniş kuralının
(ör. başka hassas port, başka genel erişim bayrağı) aynı dosyadaki gerçek sorunu yakalamasıdır.

## 19. tur: proje bağlamı, varsayılan ayarlar, değerlerle Helm

- **Terraform proje bağlamı** (`iac_tf_project.py`, `iac_tf_eval.py`): her dizin bir modüldür. `variable`
  varsayılanları, aynı dizindeki `terraform.tfvars[.json]` / `*.auto.tfvars[.json]`, `locals`; `var.x`, `local.x`, yerel
  `module.x.output`, ara değerli
  dizge, `koşul ? a : b` (koşul bilinmiyorsa iki dal aynıysa o değer), `==`/`!=`/`&&`/`||`/`!`, `lookup`, `merge`,
  `concat`, `coalesce`, `try`, `to*` dönüşümleri değerlendirilir. Varsayılansız değişken ve kaynak/veri
  başvurusu, `for`, `%{ }` bilinmiyor kalır (denetim susar). Kaynakta açıkça `count = 0` veya boş `for_each`
  yazılan blok örnek üretmediği için atlanır; değişkenle kapalı görünen kaynak sonradan değiştirilebildiği için
  denetlenir. Terraform yükleme sırası korunur: `terraform.tfvars`, ardından
  `terraform.tfvars.json`, sonra iki `*.auto.tfvars[.json]` uzantısı ortak dosya adı sırasıyla uygulanır; dosya
  sistemi yürüyüş sırası sonucu değiştirmez. Geçersiz ya da nesne olmayan JSON değer dosyası yok sayılır.
- **Yerel modüller** (`source = "./…"`/`"../…"`, proje kökü içinde): çağrı girdileri modül değişkenlerine verilir,
  modülün kaynakları o örnek için denetlenir; bulgu modül dosyasının satırında `module.<ad>.` önekli adresle ve
  kanıtta çağrı yeriyle raporlanır (en çok 4 düzey, döngü korumalı, en çok 400 örnek). Çağrı satırındaki girdiler
  ("*" kuralları) ayrıca raporlanmaya devam eder. Statik `count` ve `for_each` çağrılarının çıktıları
  `module.x[0].output` ve `module.x["key"].output` biçiminde çözülür. `for_each` için Terraform'in kabul ettiği
  statik map ve `toset(...)` kümeleri örnek anahtarı sayılır. Bu tür kanıtı `local` zincirinde ve açık
  `set(string)` değişken bildiriminde korunur; çıplak liste ile `tolist(...)` geçersiz olduğu için modül çıktı
  adresine kanıt oluşturmaz. Çıktı şekli en çok 64 örnekle sınırlıdır ve sınır aşılırsa analiz kısmi
  işaretlenir. Uzak modüllerde yalnız bilinen `terraform-aws-modules` girdileri.
- **Varsayılanı güvensiz, hiç yazılmamış ayarlar** ("(varsayılan ayar)" başlıklı, düşük/orta): S3 sürümleme ve
  erişim günlüğü (modül genelinde ayrı `aws_s3_bucket_versioning`/`_logging` kaynakları ve günlük hedefi kovalar
  dikkate alınır; askıya alınmış sürümleme sayılmaz), EBS şifreleme (hesap düzeyi varsayılan şifreleme varsa
  susar), DocumentDB/Neptune/EFS/ElastiCache/OpenSearch bekleyen veri şifrelemesi, CloudTrail günlük doğrulaması,
  SNS KMS, GCS tek tip erişim, GKE yetkili ağlar (özel uç nokta hariç), Key Vault silme koruması, ALB geçersiz
  başlıklar (ağ/ağ geçidi LB hariç). Güncel varsayılanı güvenli olanlar (S3 şifrelemesi, SQS SSE, AKS RBAC,
  Redshift şifrelemesi) bilerek eklenmedi.
- **Helm değerlerle render** (`iac_helm.py`): `Chart.yaml` olan grafikte `templates/*.yaml`, grafiğin
  `values.yaml` değerleriyle işlenir (`.Values`, `with`, `if`/`else if`/`else`, iç içe `range`, `toYaml | nindent`,
  `quote`, `default`). Tek başına `$ad := ifade` ataması, `with $ad := ifade` ve
  `range $anahtar, $değer := ifade` değişkenleri kapsam içinde çözülür. Bilinen yanlış dal atlanır (eski yanlış alarmlar kalkar), koşulu bilinmeyen dalın içindeki
  ifadeler ayrı doğru/yanlış varyantlarda incelenir; bilinen bir `range` gövdesindeki bilinmeyen `if`/`with`
  kontrolleri de ayrı varyantlara ayrılır. Altı kontrol noktasına kadar bütün kombinasyonlar, daha
  büyük şablonlarda sınırlı ve doğrusal dal kapsamı kullanılır. Doğrusal kapsam her doğrudan dalı örnekler ancak
  bütün kombinasyonları denemediği için analiz sonucu ve proje uyarıları açıkça kısmi işaretlenir. Bilinmeyen
  ya da 20 öğeyi aşan `range` de kısmi işaretlenir; büyük aralıkta ilk ve son on öğe örneklenir. Bulgu satırları
  şablon satırına eşlenir; değer dosyası yalnız SafeLoader ile okunur, proje dışına/sembolik bağa çıkılmaz.
  Sertleştirme eksikleri (K8S-013) Helm'de yine üretilmez.
- **Kubernetes ilişki doğrulaması:** RBAC zinciri yalnız doğru `rbac.authorization.k8s.io` API grubuyla,
  `RoleBinding` → `Role|ClusterRole` ve `ClusterRoleBinding` → `ClusterRole` eşleşmesiyle kurulur;
  joker rol kuralının `apiGroups` alanı liste biçiminde açıkça çekirdek grubu (`""`) veya bütün grupları (`"*"`)
  içerir ve küme bağındaki ServiceAccount öznesi açık bir ad alanı taşır. Tek rol joker bulgusunda da eksik/skaler
  `apiGroups` geçerli geniş yetki kanıtı değildir. `ExternalName` Service yerel workload seçicisi sayılmaz.
- **CI çıktı doğrulaması:** GitHub çok satırlı step output yalnız blok satırlarının her biri `$GITHUB_OUTPUT`'a
  yöneltildiyse veya bloğu kapatan kabuk grubu yöneltildiyse akar; yakındaki ilgisiz bir çıktı yazımı kanıt değildir.
  Bir step çıktısından türeyen job output yalnız tüketici job üreticiyi `needs` ile açıkça bağladıysa akar;
  bildirimin YAML sırası sonucu değiştirmez.
