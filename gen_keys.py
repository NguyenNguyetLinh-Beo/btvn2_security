# gen_keys.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os

# === Cấu hình đường dẫn lưu file ===
# Nếu bạn đặt file gen_keys.py trong C:\Users\nguye\OneDrive\Desktop\btnv2_s,
# script sẽ tạo thư mục keys dưới cùng thư mục đó.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "keys")   # => C:\Users\nguye\OneDrive\Desktop\btnv2_s\keys
os.makedirs(KEYS_DIR, exist_ok=True)

PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "signer_key.pem")
CERT_PATH = os.path.join(KEYS_DIR, "signer_cert.pem")

# === 1. Sinh khóa riêng (private key RSA 2048 bit) ===
print("🔐 Đang tạo private key RSA 2048-bit...")
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# === 2. Tạo thông tin cho certificate (tự ký - self-signed) ===
print("📜 Đang tạo chứng chỉ tự ký (self-signed certificate)...")

# Thông tin người ký (đã cập nhật theo yêu cầu của bạn)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Thai Nguyen"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Thai Nguyen"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "K58KTP"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "MSSV: k225480106039"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Nguyễn Nguyệt Linh"),
    x509.NameAttribute(NameOID.EMAIL_ADDRESS, "0363650618@example.invalid"),  # SDT để vào email trường nếu muốn tham chiếu
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow() - timedelta(minutes=1))
    .not_valid_after(datetime.utcnow() + timedelta(days=365))  # Hợp lệ 1 năm
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    .sign(private_key, hashes.SHA256())
)

# === 3. Ghi file private key ===
with open(PRIVATE_KEY_PATH, "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),  # Nếu muốn mật khẩu, đổi thành BestAvailableEncryption(b"pass")
        )
    )
print(f"✅ Đã lưu private key tại: {PRIVATE_KEY_PATH}")

# === 4. Ghi file certificate ===
with open(CERT_PATH, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
print(f"✅ Đã lưu certificate tại: {CERT_PATH}")

# === Hoàn tất ===
print("\n🎉 Tạo cặp khóa & chứng chỉ tự ký thành công!")
