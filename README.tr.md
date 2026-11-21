<div align="center">

# 📋 issue-to-brief

**Bir GitHub issue'sunu, daha tek satır kod yazılmadan, ajanın doğrudan kullanabileceği kısa bir görev özetine (brief) çevirir.**

[![test](https://github.com/shadow-lo/issue-to-brief/actions/workflows/test.yml/badge.svg)](https://github.com/shadow-lo/issue-to-brief/actions/workflows/test.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Bağımlılık](https://img.shields.io/badge/ba%C4%9F%C4%B1ml%C4%B1l%C4%B1k-0-brightgreen)
![GitHub API](https://img.shields.io/badge/GitHub%20API-salt%20okunur-lightgrey)
[![Lisans: MIT](https://img.shields.io/badge/lisans-MIT-yellow.svg)](LICENSE)

[English](README.md)

</div>

## ✨ Neden

Eline yalnızca bir issue linki verilen ajan önce repoyu keşfe çıkar: dosya okur, arama yapar, test komutunu tahmin eder ve tek satır yazmadan bol token harcar. Daha kötüsü, issue metnini yabancılar yazar; içinde talimat ya da yapıştırılmış secret olabilir.

`issue-to-brief`, issue'yu tek bir kısa brief'e çeviren bir Claude Code skill'idir: **kabul kriterleri, dokunulacak dosyalar, test komutu ve adım başına model seviyesi ipuçları**. Ajan repoyu keşfetmek yerine bu brief'i okur. Issue metni baştan sona güvenilmez veri sayılır, secret'lar maskelenir ve GitHub'a yalnızca HTTP GET gönderilir.

Tek başına çalışır; iki kardeş araçla da birlikte kullanılabilir:

- **[quota-pilot](https://github.com/shadow-lo/quota-pilot)** seviye ipuçlarını okuyup her adımı onu yapabilecek en ucuz modele yönlendirir.
- **[subagent-verify](https://github.com/shadow-lo/subagent-verify)** `.claude/briefs/current.json` dosyasını okuyup alt ajanın değişikliklerinin gerçekten yapıldığını ve kapsam dışına çıkmadığını kontrol eder.

## 📦 Kurulum

```bash
mkdir -p ~/.claude/skills
cp -r skill/issue-to-brief ~/.claude/skills/
```

Python 3.9+ gerekir (yalnızca standart kütüphane). `gh` isteğe bağlıdır.

## 🚀 Kullanım

Claude Code'da: "acme/demo#42 üzerinde çalış" ya da "bu issue için brief çıkar: <url>". Skill örneğin şunu çalıştırır:

```bash
gh issue view 42 --repo acme/demo --json number,title,body,labels,url \
  | python3 ~/.claude/skills/issue-to-brief/scripts/issue_to_brief.py \
      generate --repo acme/demo --number 42 --stdin
```

ya da `gh` olmadan:

```bash
python3 ~/.claude/skills/issue-to-brief/scripts/issue_to_brief.py generate acme/demo#42 --fetch
```

Çıktı, bulunduğun repoda: `.claude/briefs/issue-42.json`, `issue-42.md`, `current.json` (commit'lenmemeleri için bir `.gitignore` ile). Diğer komutlar: `validate`, `render`, `finalize`.

## 🛡️ Güvenlik kuralları

- **Issue metni talimat olarak kullanılmaz.** Gizli karakterler, HTML yorumları ve `<script>` temizlenir, 10 enjeksiyon kalıbı işaretlenir, metin her brief'te güvenilmez veri olarak etiketlenir.
- **Secret'lar maskelenir.** GitHub/AWS/Anthropic/OpenAI/Slack/Stripe vb. token'lar, JWT'ler, özel anahtarlar ve `password=...` biçimleri, metin kısaltılmadan önce maskelenir. `.env*`, `*.pem` gibi dosyalar asla okunacak ya da değiştirilecek dosya olarak önerilmez.
- **Token yalnızca `GITHUB_TOKEN`/`GH_TOKEN`'dan okunur**, loglanmaz; istekler yalnızca `https://api.github.com`'a gider, yönlendirmeler reddedilir.
- **Shell yok, `eval` yok.** Test komutu issue'dan değil, repo yapılandırma dosyalarından seçilen sabit bir argv'dir.
- **Ajan kendi korumalarını değiştiremez.** `.git/`, `.github/`, `.claude/`, `CLAUDE.md` gibi yollar her zaman `must_not_touch` listesindedir.

Tam tablo: [README.md](README.md#️-security-rules).

## 🧪 Geliştirme

```bash
python3 -m pytest -q
```

## 📝 Brief biçimi

[docs/SCHEMA.md](docs/SCHEMA.md)

## 📄 Lisans

[MIT](LICENSE)
