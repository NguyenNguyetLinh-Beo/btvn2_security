# btvn2_security
## BÀI TẬP VỀ NHÀ – MÔN: AN TOÀN VÀ BẢO MẬT THÔNG TIN
Chủ đề: Chữ ký số trong file PDF
Giảng viên: Đỗ Duy Cốp
Thời điểm giao: 2025-10-24 11:45
Đối tượng áp dụng: Toàn bộ sv lớp học phần 58KTPM
Hạn nộp: Sv upload tất cả lên github trước 2025-10-31 23:59:59
## Nguyễn Nguyệt Linh - MSSV: K225480106039
## I. MÔ TẢ CHUNG
Sinh viên thực hiện báo cáo và thực hành: phân tích và hiện thực việc nhúng, xác thực chữ ký số trong file PDF.
Phải nêu rõ chuẩn tham chiếu (PDF 1.7 / PDF 2.0, PAdES/ETSI) và sử dụng công cụ thực thi (ví dụ iText7, OpenSSL, PyPDF, pdf-lib).
## II. CÁC YÊU CẦU CỤ THỂ
### 1) Cấu trúc PDF liên quan chữ ký (Nghiên cứu)  
Catalog: entry root của tài liệu; có thể trỏ tới /Pages và /AcroForm.  
Pages tree & Page object: cấu trúc trang; mỗi page có /Contents chứa content stream.    
Resources: font, xobject, v.v. dùng bởi content stream.   
Content streams: chuỗi lệnh PDF hiển thị nội dung page.  
XObject: hình ảnh/form XObject nhúng.  
AcroForm: nơi chứa form fields (các trường điền, gồm cả signature field).  
Signature field (widget): field trên trang (visible / invisible) trỏ tới Signature dictionary.  
Signature dictionary (/Sig): object chứa metadata chữ ký (ví dụ /Filter, /SubFilter, /Contents, /ByteRange, /M, ...).  
/ByteRange: mảng hai cặp offset/length cho vùng tài liệu được hash (loại bỏ vùng chứa /Contents).  
/Contents: chứa blob chữ ký PKCS#7 (DER) — thường là một string nhị phân lớn được đệm/đặt kích thước cố định.  
Incremental updates: PDF cho phép cập nhật theo kiểu tăng dần (append-only). Chữ ký thường là incremental update: ký bản hiện tại mà thêm vào cuối file.  
DSS (Document Security Store) (PAdES): một cấu trúc (thường ở Catalog hoặc ở bộ metadata của PAdES) để lưu chứng thư, OCSP, CRL, timestamp tokens cho LTV.  
Object refs quan trọng — vai trò ngắn gọn  
Catalog → trỏ /AcroForm (nếu có): nơi định nghĩa form fields.  
/AcroForm → /Fields[] chứa SigField (reference to widget).  
SigField (Widget annotation) → /V trỏ tới SigDict.  
SigDict (Signature dictionary) chứa /Contents, /ByteRange, /Filter, /SubFilter, /M, /Name, ...  
/Contents — nơi chèn PKCS#7/CMS DER (chữ ký).  
/ByteRange — chỉ rõ phần byte dùng để tính hash (loại bỏ /Contents).  
DSS or VRI (PAdES) — lưu chứng thư/OCSP/CRL/time-stamps để hỗ trợ LTV (long-term validation).  
Đầu ra yêu cầu   
1 trang tóm tắt văn bản + 1 sơ đồ object (ví dụ:  
Catalog → Pages → Page → /Contents   
Catalog → /AcroForm → Fields → SigField → SigDict (/Contents, /ByteRange)).   
### 2) Thời gian ký được lưu ở đâu?
Vị trí có thể chứa thông tin thời gian ký:
1. /M trong Signature dictionary
Dạng: text (PDF date string, ví dụ D:20251027...).
Ghi chú: chỉ là metadata, không phải bằng chứng thời gian pháp lý; dễ bị sửa nếu file bị chỉnh sửa (trừ khi đã được timestamped về mặt cryptographic).
2. Timestamp token (RFC 3161) (embedded trong PKCS#7)
Là timestamp do TSA (Time Stamping Authority) ký; thường nằm trong PKCS#7 như attribute timeStampToken.
Có giá trị pháp lý/cryptographic vì timestamp token do TSA ký, biểu thị thời điểm chữ ký được tạo.
3. Document timestamp object (PAdES)
PAdES định nghĩa các cách embedding document time-stamp objects, khác với signature timestamp; dùng để chứng thực trạng thái document độc lập với người ký.
4. DSS (Document Security Store) / VRI
DSS có thể lưu timestamp token, chứng thư, OCSP, CRL liên quan để hỗ trợ LTV.
Khác biệt chính giữa /M và RFC3161 timestamp:
/M: chỉ chuỗi thời gian do creator thêm, không có chữ ký độc lập, có thể bị giả mạo.
RFC3161 timestamp: token do TSA ký bằng private key của TSA; bảo đảm thời gian không thể bị thay đổi mà không làm hỏng chữ ký TSA (vì token có chữ ký số của TSA). Do đó RFC3161 có độ tin cậy cryptographic cao hơn.
### 3) Các bước tạo và lưu chữ ký trong PDF (đã có private RSA)
- Viết script/code thực hiện tuần tự:
Lưu ý bảo mật: sinh key mới cho mục học tập; không đẩy private key thực tế của tổ chức lên repo công khai.
Tổng quy trình (một lần chạy — incremental signing)
1. Chuẩn bị file PDF gốc (original.pdf).
Chọn file, đảm bảo không có signature field trước đó (hoặc dùng copy).
2. Tạo Signature field (AcroForm):
Thêm SigField vào /AcroForm (có thể invisible).
Thêm widget annotation trên page nếu muốn visible signature appearance.
3. Reserve vùng /Contents:
Khi thêm SigDict, đặt /Contents là một string object có fixed length (ví dụ 8192 bytes hoặc 32768 bytes) — toàn bộ vùng này ban đầu là null bytes hoặc spaces.
PDF sẽ chứa /ByteRange mà loại trừ phần /Contents dự kiến.
Quan trọng: độ dài /Contents phải đủ lớn để chứa blob PKCS#7 DER sau này.
4. Xác định /ByteRange:
/ByteRange [0, offset1, offset2, length2] — hai đoạn: từ đầu file đến trước vùng /Contents, và từ sau vùng /Contents tới cuối file.
Tính toán offset chính xác dựa trên vị trí bytes của string /Contents.
5. Tính hash trên vùng ByteRange:
Dùng SHA-256 (hoặc SHA-512 tùy yêu cầu) trên concatenation của hai đoạn xác định trong /ByteRange.
Kết quả là messageDigest.
6. Tạo PKCS#7/CMS (detached) hoặc CAdES:
Tạo SignedData detached (chứa messageDigest attribute, signingTime, contentType, và certificate chain).
RSA padding: PKCS#1 v1.5 là phổ biến, RSA-PSS được khuyến nghị nếu muốn mạnh hơn.
Kích thước khóa: ≥ 2048 bits (khuyến nghị 3072 hoặc 4096 cho cao hơn).
(Tùy chọn) Gửi messageDigest tới TSA để nhận RFC3161 timestamp token và chèn token này vào PKCS#7 (có thể nested hoặc như một unsigned attribute để tạo CAdES-T).
7. Chèn blob DER PKCS#7 vào /Contents:
Viết blob DER (nhị phân) vào vị trí /Contents đã reserve, thường dưới dạng hex-escaped hoặc string literal (PDF string).
Nếu blob nhỏ hơn reserved size: duti nén / padding (null bytes). Nếu lớn hơn: phải reserve lớn hơn từ đầu.
8. Ghi incremental update:
Ghi phần thay đổi (các object mới, sửa object) vào file PDF theo chế độ append (incremental update). Điều này để giữ chữ ký hợp lệ với phần trước.
9. (LTV) Cập nhật DSS với Certs, OCSPs, CRLs, VRI:
Để đạt LTV, lưu chứng thư intermediate/root, responses OCSP hoặc CRL, và timestamp token trong DSS object theo PAdES.
Hash alg, padding, vị trí lưu trong PKCS#7 (tóm tắt)
messageDigest — hash của vùng ByteRange, thường SHA-256 (ví dụ).
signature — RSA sign over SignedAttributes (chứa messageDigest, signingTime, v.v).
RSA padding: PKCS#1 v1.5 (cũ) hoặc RSA-PSS (khuyến nghị) — phải tương thích với SubFilter.
Kích thước khoá: ≥ 2048 bit.
Trong PKCS#7: certificate chain nằm ở phần certificates (signed data), timestamp token (RFC3161) nằm trong unsignedAttributes (nếu thêm sau khi ký) hoặc attribute timeStampToken.
### 4) Các bước xác thực chữ ký trên PDF đã ký
- Các bước kiểm tra:
Khi có signed.pdf, thực hiện các bước sau để kiểm tra tính hợp lệ:

1. Đọc Signature dictionary: lấy /Contents, /ByteRange, /SubFilter, /M.
2. Tách PKCS#7 từ /Contents: trích blob DER.
3. Kiểm tra định dạng PKCS#7: parse SignedData, lấy signedAttributes (nếu có) và messageDigest attribute.
4. Tính lại hash: từ /ByteRange (nối hai vùng) tính hash (SHA-256) và so sánh với messageDigest. Nếu khác → tampered.
5. Xác thực chữ ký: verify signature bằng public key từ cert signer (ktra RSA/ padding).
6. Kiểm tra chain → root trusted CA: xây dựng và validate chain; nếu root không trusted → cảnh báo (với self-signed test, bạn có thể trust local cert).
7. Kiểm tra OCSP/CRL: nếu PKCS#7 chứa AIA/OCSP info hoặc DSS có responses, kiểm tra certificate status.
8. Kiểm tra timestamp token: nếu có RFC3161 token, verify token bằng cert của TSA; token cho biết thời điểm chữ ký được timestamped.
9. Kiểm tra incremental updates: xác minh rằng phần tài liệu sau khi ký không thay đổi bộ các byte đã được hash (phát hiện sửa đổi).
10. Lưu logs: log chi tiết mọi bước kiểm tra (hash match, sign verify, chain status, OCSP, timestamp).

## III. YÊU CẦU NỘP BÀI
1. Báo cáo PDF ≤ 6 trang: mô tả cấu trúc, thời gian ký, rủi ro bảo mật.
2. Code + README (Git repo hoặc zip).
3. Demo files: original.pdf, signed.pdf, tampered.pdf.
4. (Tuỳ chọn) Video 3–5 phút demo kết quả.

## IV. TIÊU CHÍ CHẤM
- Lý thuyết & cấu trúc PDF/chữ ký: 25%
- Quy trình tạo chữ ký đúng kỹ thuật: 30%
- Xác thực đầy đủ (chain, OCSP, timestamp): 25%
- Code & demo rõ ràng: 15%
- Sáng tạo mở rộng (LTV, PAdES): 5%

## V. GHI CHÚ AN TOÀN
- Vẫn lưu private key (sinh random) trong repo. Tránh dùng private key thương mại.
- Dùng RSA ≥ 2048-bit và SHA-256 hoặc mạnh hơn.
- Có thể dùng RSA-PSS thay cho PKCS#1 v1.5.
- Khuyến khích giải thích rủi ro: padding oracle, replay, key leak.

## VI. GỢI Ý CÔNG CỤ
- OpenSSL, iText7/BouncyCastle, pypdf/PyPDF2.
- Tham khảo chuẩn PDF: ISO 32000-2 (PDF 2.0) và ETSI EN 319 142 (PAdES).
