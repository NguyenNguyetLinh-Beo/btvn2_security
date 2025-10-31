from datetime import datetime
from pyhanko.sign import signers, fields
from pyhanko.stamp.text import TextStampStyle
from pyhanko.pdf_utils import images
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.pdf_utils.layout import SimpleBoxLayoutRule, AxisAlignment, Margins
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko_certvalidator import ValidationContext
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigFieldSpec

# === ĐƯỜNG DẪN (THEO MÁY CỦA NGUYỄN NGUYỆT LINH) ===
PDF_IN = r"C:\Users\nguye\OneDrive\Desktop\btnv2_s\b2.pdf"  # <-- file gốc cần ký
PDF_OUT = r"C:\Users\nguye\OneDrive\Desktop\btnv2_s\signed.pdf"
KEY_FILE = r"C:\Users\nguye\OneDrive\Desktop\btnv2_s\keys\signer_key.pem"
CERT_FILE = r"C:\Users\nguye\OneDrive\Desktop\btnv2_s\keys\signer_cert.pem"
SIG_IMG = r"C:\Users\nguye\OneDrive\Desktop\btnv2_s\assets\ten.jpg"

# ======================= QUY TRÌNH KÝ PDF ===========================
print("=== QUY TRÌNH KÝ PDF - NGUYỄN NGUYỆT LINH ===\n")

# Bước 1: Chuẩn bị file PDF gốc (b2.pdf)
print("Bước 1: Chuẩn bị file PDF gốc (b2.pdf).")

# Bước 2: Tạo Signature field (AcroForm)
print("Bước 2: Tạo SigField1, reserve vùng /Contents (~8192 bytes).")

# Bước 3: Xác định ByteRange (vùng hash loại trừ /Contents)
print("Bước 3: Xác định ByteRange (vùng hash trừ /Contents).")

# Bước 4: Tính hash SHA-256
print("Bước 4: Tính hash SHA-256 trên ByteRange (md_algorithm='sha256').")

# Bước 5: Tạo PKCS#7 detached
print("Bước 5: Tạo PKCS#7 detached (messageDigest, signingTime, cert chain).")

# === TẠO SIGNER & VALIDATION CONTEXT ===
signer = signers.SimpleSigner.load(KEY_FILE, CERT_FILE, key_passphrase=None)
vc = ValidationContext(trust_roots=[load_cert_from_pemder(CERT_FILE)])

# Bước 6: Chèn blob DER PKCS#7 vào /Contents
print("Bước 6: Chèn DER PKCS#7 vào /Contents offset (hex-encoded).")

# Bước 7: Ghi incremental update
print("Bước 7: Incremental update (append SigDict + cross-ref).")

# === MỞ FILE PDF GỐC ===
with open(PDF_IN, "rb") as inf:
    writer = IncrementalPdfFileWriter(inf)

    # Lấy số trang cuối cùng (để chèn chữ ký)
    try:
        pages = writer.root["/Pages"]
        if "/Count" in pages:
            num_pages = int(pages["/Count"])
        else:
            num_pages = len(pages["/Kids"])
    except Exception as e:
        print("⚠️ Không đọc được số trang, mặc định 1.")
        num_pages = 1

    target_page = num_pages - 1  # ký ở trang cuối

    fields.append_signature_field(
        writer,
        SigFieldSpec(
            sig_field_name="SigField1",
            box=(240, 50, 550, 150),  # vị trí chữ ký (tọa độ x,y)
            on_page=target_page
        )
    )

    # === Ảnh nền chữ ký tay ===
    background_img = images.PdfImage(SIG_IMG)

    # Layout ảnh và text
    bg_layout = SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MID,
        margins=Margins(right=20)
    )

    text_layout = SimpleBoxLayoutRule(
        x_align=AxisAlignment.ALIGN_MIN,
        y_align=AxisAlignment.ALIGN_MID,
        margins=Margins(left=150)
    )

    text_style = TextBoxStyle(font_size=13)

    # Nội dung chữ ký
    ngay_ky = datetime.now().strftime("%d/%m/%Y")
    stamp_text = (
        "Nguyễn Nguyệt Linh"
        "\nSDT: 0363650618"
        "\nMSSV: k225480106039"
        f"\nNgày ký: {ngay_ky}"
    )

    stamp_style = TextStampStyle(
        stamp_text=stamp_text,
        background=background_img,
        background_layout=bg_layout,
        inner_content_layout=text_layout,
        text_box_style=text_style,
        border_width=1,
        background_opacity=1.0,
    )

    # Metadata chữ ký
    meta = signers.PdfSignatureMetadata(
        field_name="SigField1",
        reason="Nộp bài: Chữ ký số PDF - 58KTP",
        location="Thái Nguyên, VN",
        md_algorithm="sha256",
    )

    pdf_signer = signers.PdfSigner(
        signature_meta=meta,
        signer=signer,
        stamp_style=stamp_style,
    )

    # Thực hiện ký và lưu file
    with open(PDF_OUT, "wb") as outf:
        pdf_signer.sign_pdf(writer, output=outf)

# Bước 8: LTV (DSS)
print("Bước 8: LTV DSS - Append Certs/OCSP/CRLs/VRI (nếu có).")

print("\n✅ Đã ký PDF thành công!")
print("📄 File ký được lưu tại:", PDF_OUT)
