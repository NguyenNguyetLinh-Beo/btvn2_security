#!/usr/bin/env python3
"""
verify_pdf_signature_full_v2.py
Phiên bản tinh chỉnh nhẹ — cùng chức năng, cùng kết quả log, khác cách viết.
"""

import os, sys, hashlib, datetime, traceback, binascii
from PyPDF2 import PdfReader
from asn1crypto import cms, core, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

try:
    import requests
except Exception:
    requests = None

LOG_PATH = os.path.join(os.getcwd(), "verify_log.txt")


# ======= Logging =======
def log(msg: str):
    """Ghi log ra màn hình và file verify_log.txt"""
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def clear_log():
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)


# ======= PDF Signature extraction =======
def read_sigdict(pdf_path: str):
    reader = PdfReader(pdf_path)
    fields = reader.get_fields() or {}
    log(f"Found fields: {list(fields.keys())}")

    for page_idx, page in enumerate(reader.pages):
        annots = page.get("/Annots")
        if not annots:
            continue

        for annot_ref in annots:
            annot = annot_ref.get_object()
            if annot.get("/Subtype") == "/Widget" and annot.get("/FT") == "/Sig":
                sig_obj = annot.get("/V")
                if not sig_obj:
                    log(f"Signature field on page {page_idx+1} is empty.")
                    continue
                sig = sig_obj.get_object()
                return {
                    "page": page_idx + 1,
                    "field_name": annot.get("/T"),
                    "sig_dict": sig,
                    "reader": reader,
                }
    return None


def extract_contents_and_byterange(sig_dict):
    contents = sig_dict.get("/Contents")
    if contents is None:
        raise ValueError("No /Contents in signature dictionary")

    if isinstance(contents, (bytes, bytearray)):
        pkcs7_bytes = bytes(contents)
    else:
        try:
            pkcs7_bytes = contents.get_data()
        except Exception:
            pkcs7_bytes = bytes(contents)

    br = sig_dict.get("/ByteRange")
    if not br or len(br) != 4:
        raise ValueError(f"Invalid /ByteRange: {br}")
    return pkcs7_bytes, [int(x) for x in br]


# ======= Utility =======
def save_pkcs7(pkcs7_bytes, out_path):
    with open(out_path, "wb") as f:
        f.write(pkcs7_bytes)
    log(f"Saved PKCS#7 blob to {out_path} ({len(pkcs7_bytes)} bytes)")


def compute_hash_of_byterange(pdf_path, byterange, algo="sha256"):
    with open(pdf_path, "rb") as f:
        data = f.read()
    part1 = data[byterange[0] : byterange[0] + byterange[1]]
    part2 = data[byterange[2] : byterange[2] + byterange[3]]
    m = hashlib.new(algo)
    m.update(part1)
    m.update(part2)
    return m.digest(), m.hexdigest()


# ======= PKCS#7 Parsing =======
def parse_pkcs7(pkcs7_bytes):
    ci = cms.ContentInfo.load(pkcs7_bytes)
    if ci["content_type"].native != "signed_data":
        raise ValueError("PKCS#7 content is not SignedData")
    sd = ci["content"]
    return sd, sd["signer_infos"], sd["certificates"]


def find_signer_cert(sd, signer_info):
    sid = signer_info["sid"]
    certs = sd["certificates"]

    signer_cert = None
    if sid.name == "issuer_and_serial_number":
        issuer = sid.chosen["issuer"]
        serial = sid.chosen["serial_number"].native
        for c in certs:
            if isinstance(c.chosen, asn1_x509.Certificate):
                cc = c.chosen
                if cc.serial_number == serial and cc.issuer == issuer:
                    signer_cert = cc
                    break
    else:
        for c in certs:
            if isinstance(c.chosen, asn1_x509.Certificate):
                signer_cert = signer_cert or c.chosen

    message_digest = None
    signed_attrs = signer_info["signed_attrs"]
    if signed_attrs is not None:
        for attr in signed_attrs:
            if attr["type"].dotted == "1.2.840.113549.1.9.4":  # messageDigest
                vals = attr["values"]
                if vals:
                    message_digest = bytes(vals[0].native)
                break
    return signer_cert, message_digest, signed_attrs


def asn1_to_crypto_cert(asn1_cert):
    return x509.load_der_x509_certificate(asn1_cert.dump(), default_backend())


def verify_signature(signer_cert, signer_info):
    signature = signer_info["signature"].native
    signed_attrs_der = signer_info["signed_attrs"].dump()
    digest_alg = signer_info["digest_algorithm"]["algorithm"].native

    hash_alg = {
        "sha1": hashes.SHA1(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }.get(digest_alg, None)
    if not hash_alg:
        raise ValueError(f"Unsupported digest algorithm: {digest_alg}")

    try:
        signer_cert.public_key().verify(signature, signed_attrs_der, padding.PKCS1v15(), hash_alg)
        return True, f"Signature verified OK ({digest_alg})"
    except Exception as e:
        return False, str(e)


# ======= Chain & Timestamp =======
def check_incremental_update(pdf_path, br):
    end = br[2] + br[3]
    file_len = os.path.getsize(pdf_path)
    extra = file_len - end
    if extra > 0:
        return False, f"{extra} extra bytes after ByteRange — possible incremental update"
    return True, "No extra data after ByteRange end"


def check_timestamp_token(signer_info):
    try:
        ua = signer_info.get("unsigned_attrs")
        if ua:
            for attr in ua:
                if attr["type"].dotted == "1.2.840.113549.1.9.16.2.14":
                    return True, "Timestamp token found."
        return False, "No timestamp token."
    except Exception as e:
        return False, f"Error checking timestamp token: {e}"


# ======= Main =======
def main(pdf_path, trust_paths=None, out_p7s=None):
    clear_log()
    log(f"Starting verification for {pdf_path}")

    try:
        siginfo = read_sigdict(pdf_path)
        if not siginfo:
            log("No signature found.")
            return

        sig_dict = siginfo["sig_dict"]
        pkcs7_bytes, br = extract_contents_and_byterange(sig_dict)
        out_p7s = out_p7s or (os.path.splitext(pdf_path)[0] + ".p7s")
        save_pkcs7(pkcs7_bytes, out_p7s)

        sd, signer_infos, certs = parse_pkcs7(pkcs7_bytes)
        signer_info = signer_infos[0]
        signer_cert_asn1, msg_digest, _ = find_signer_cert(sd, signer_info)
        signer_cert_crypto = asn1_to_crypto_cert(signer_cert_asn1)

        log(f"Signer: {signer_cert_crypto.subject.rfc4514_string()}")

        computed_digest, hex_digest = compute_hash_of_byterange(pdf_path, br)
        log(f"Computed digest: {hex_digest}")

        if msg_digest:
            if msg_digest == computed_digest:
                log("✅ messageDigest matches computed hash.")
            else:
                log("❌ messageDigest mismatch — file may be altered.")
        else:
            log("⚠️ No messageDigest attribute present.")

        ok, msg = verify_signature(signer_cert_crypto, signer_info)
        log("✅ " + msg if ok else "❌ " + msg)

        ts_ok, ts_msg = check_timestamp_token(signer_info)
        log(f"Timestamp token: {ts_msg}")

        inc_ok, inc_msg = check_incremental_update(pdf_path, br)
        log(f"Incremental update: {inc_msg}")

        log("Verification completed.")
    except Exception as e:
        log(f"Error: {e}\n{traceback.format_exc()}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_pdf_signature_full_v2.py <pdf> [trust_cert.pem]")
        sys.exit(1)
    pdf = sys.argv[1]
    trust = sys.argv[2:] if len(sys.argv) > 2 else None
    main(pdf, trust_paths=trust)
