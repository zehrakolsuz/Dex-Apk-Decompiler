# 📱 APK Decompiler (by Zehra Kolsuz)

Bu araç, Android APK dosyalarının içeriğini analiz etmek ve içindeki DEX (Dalvik Executable) kodlarını okunabilir hale getirmek amacıyla geliştirilmiştir. Özellikle adli bilişim, güvenlik analizleri ve tersine mühendislik süreçlerinde kullanılabilir.

## 📦 Özellikler

- `apktool` ile APK dosyasını açar
- DEX içindeki string, tip, field, method ve class tablolarını ayrıştırır
- Dalvik bytecode komutlarını basitleştirilmiş Java benzeri koda dönüştürür
- Her sınıf için ayrı okunabilir kod üretir

## 🛠️ Gereksinimler

- Python 3.6 veya üzeri
- [apktool] (sistem PATH'ine eklenecek)
- Python modülleri:
  - `colorama`

Kurmak için:

```bash
pip install colorama
```

## 🚀 Kullanım

```bash
python3 apk_decompiler.py --input path/to/file.apk --output output_folder
```

### Parametreler

| Parametre   | Açıklama                            | Gerekli                    |
|-------------|-------------------------------------|----------------------------|
| `--input`   | APK dosyasının yolu                 | ✅                         |
| `--output`  | Çıktıların yazılacağı klasör        | ❌ (varsayılan: `output`)  |

## ⚙️ Nasıl Çalışır?

1. `apktool` ile APK dosyası ayrıştırılır.
2. DEX dosyaları bulunur.
3. Her DEX dosyası analiz edilerek:
   - Header bilgileri okunur
   - String, type, field, method, class tablosu ayrıştırılır
   - Class’lara ait Dalvik bytecode, anlaşılır kodlara dönüştürülür
4. Her sınıf ayrı bir bölümde `decompiled_*.txt` dosyasına yazılır

### Örnek Çıktı

```java
Class: com/example/MyActivity
{
  v0 = "Merhaba";
  v1 = v0;
  if (v1 != 0) goto label_10;
  return;
}
```

## 📜 Desteklenen Opcode’lar

Program aşağıdaki türden opcode'ları desteklemektedir:

- `move`, `return`, `const`, `goto`, `if-*`
- `invoke-virtual`, `invoke-static`, `invoke-direct` vb.
- `iget`, `iput`, `sget`, `sput`
- `add-int`, `sub-int`, `mul-int` ve benzeri matematiksel işlemler
- `new-instance`, `new-array`
- `cmp`, `monitor-enter`, `throw` vb.

> ⚠️ Tüm opcode’lar birebir desteklenmez. Bazı karmaşık kontrol akışları sadece açıklama olarak gösterilir (`// Unknown opcode`, `// fill array with data` vs.).

## 🐛 Sık Karşılaşılan Hatalar

| Hata | Açıklama |
|------|----------|
| `apktool bulunamadı` | `apktool` sistemde kurulu değil ya da PATH'e eklenmemiş olabilir. |
| `DEX ayrıştırma hatası` | DEX dosyası bozuk olabilir ya da farklı bir format kullanıyor olabilir. |
| `UnicodeDecodeError` | Bazı string veriler bozulmuş olabilir; otomatik olarak `replace` ile işlenir. |
| `Beklenmedik hata` | Kodda bilinmeyen bir opcode ya da beklenmeyen durum oluşmuş olabilir. |

## 🤝 Katkıda Bulunmak

Katkılarınızı bekliyoruz! Kod, dökümantasyon veya test desteği sağlamak isterseniz:

1. Fork’layın
2. Değişikliklerinizi yapın
3. Pull Request (PR) gönderin

## 👩‍💻 Geliştirici

**Zehra Kolsuz**    


## 📝 Lisans

Bu proje MIT Lisansı ile lisanslanmıştır.
