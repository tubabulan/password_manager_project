import psycopg2
from config import DB_CONFIG
from encryption import encrypt_password, decrypt_password  # AES şifreleme işlevleri
from password_utils import generate_password, evaluate_password_strength  # Parola üretici ve değerlendirici

def get_db_connection():
    connection = psycopg2.connect(
        dbname=DB_CONFIG['dbname'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        host=DB_CONFIG['host']
    )
    return connection

def register_user(email, password):
    encrypted_password = encrypt_password(password)
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO users (email, password_hash) VALUES (%s, %s)",
        (email, encrypted_password)
    )

    conn.commit()
    cur.close()
    conn.close()
    print("✅ Kullanıcı başarıyla kaydedildi!\n")

def login_user(email, password):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT password_hash FROM users WHERE email = %s", (email,))
    result = cur.fetchone()

    if result:
        stored_hash = result[0]
        decrypted_password = decrypt_password(stored_hash)

        if password == decrypted_password:
            print("✅ Giriş başarılı!\n")
        else:
            print("❌ Yanlış şifre!\n")
    else:
        print("❌ Kullanıcı bulunamadı!\n")

    cur.close()
    conn.close()

def generate_and_evaluate_password():
    generated_password = generate_password(16)
    print("🔐 Oluşturulan Parola:", generated_password)
    password_strength = evaluate_password_strength(generated_password)
    print("🔎 Parola Gücü:", password_strength, "\n")

def get_password_choice():
    while True:
        print("\nŞifre seçimi:")
        print("1. Şifremi kendim gireceğim")
        print("2. Sistem benim için güçlü bir şifre oluştursun")
        choice = input("Seçiminiz (1/2): ").strip()

        if choice == "1":
            return input("Şifrenizi girin: ")
        elif choice == "2":
            password = generate_password(16)
            print("🔐 Oluşturulan Parola:", password)
            strength = evaluate_password_strength(password)
            print("🔎 Parola Gücü:", strength)
            return password
        else:
            print("⚠️ Geçersiz seçim, lütfen 1 ya da 2 girin.")

def main():
    while True:
        print("===== MENÜ =====")
        print("1. Kayıt Ol")
        print("2. Giriş Yap")
        print("3. Parola Oluştur ve Değerlendir")
        print("4. Çıkış")
        choice = input("Bir seçenek girin (1-4): ").strip()

        if choice == "1":
            email = input("E-posta adresinizi girin: ")
            password = get_password_choice()
            register_user(email, password)
        elif choice == "2":
            email = input("E-posta adresinizi girin: ")
            password = input("Şifrenizi girin: ")
            login_user(email, password)
        elif choice == "3":
            generate_and_evaluate_password()
        elif choice == "4":
            print("👋 Programdan çıkılıyor...")
            break
        else:
            print("⚠️ Geçersiz seçenek! Lütfen 1-4 arasında bir seçim yapın.\n")

if __name__ == "__main__":
    main()
