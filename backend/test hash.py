import requests

# Senin başarılı olduğun anahtar
BAZAAR_API_KEY = "d2cce8d1801ad6ac8b043a71fec04ee3bca3f3a94be3e3f3"

# Test için Emotet hash'i
TEST_HASH = "75bf972e1ce97078abbb2f2aca9c0dcd5b7756809a1504f184f10030b6fe32ed"

url = "https://mb-api.abuse.ch/api/v1/"

# 'get_info' sorgusu için selector GEREKMEZ, sadece hash yeterlidir.
data = {
    "query": "get_info",
    "hash": TEST_HASH
}

# 🔥 KRİTİK DÜZELTME: Başarılı olan 'Auth-Key' başlığını kullanıyoruz.
headers = {
    "Auth-Key": BAZAAR_API_KEY 
}

print(f"📡 Bazaar'a bağlanılıyor (Auth-Key modunda)...")

try:
    # MalwareBazaar 'data=data' (form-data) formatını tercih eder.
    response = requests.post(url, data=data, headers=headers, timeout=15)
    
    if response.status_code == 200:
        json_data = response.json()
        if json_data.get("query_status") == "ok":
            print("\n✅ BAŞARILI! Kimlik doğrulama sağlandı.")
            print(f"🦠 Tespit Edilen Zararlı: {json_data['data'][0]['signature']}")
        else:
            print(f"\n⚠️ API Yanıtı: {json_data.get('query_status')}")
            print(f"Detay: {json_data}")
    elif response.status_code == 401:
        print("\n❌ HATA: 401 Unauthorized!")
        print("👉 'Auth-Key' başlığına rağmen reddedildi. Anahtarın sonuna boşluk girmediğinden emin ol.")
    else:
        print(f"\n❌ Sunucu Hatası: {response.status_code}")

except Exception as e:
    print(f"\n💥 Bağlantı Hatası: {e}")