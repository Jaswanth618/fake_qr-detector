from pathlib import Path
import qrcode

cases = {
    "01-safe-example.png": "https://example.com",
    "02-payment-phishing.png": "http://paytm-secure.test/verify-payment?ref=DEMO2026",
    "03-lookalike-domain.png": "https://gpay-bonus.test/claim",
    "04-ip-address-link.png": "http://192.0.2.45/login",
    "05-long-redirect.png": "https://secure-wallet.test/verify/account/urgent/claim?token=DEMO-ONLY-DO-NOT-USE-REAL-DATA",
}

output = Path("test-qr-codes")
output.mkdir(exist_ok=True)

for filename, data in cases.items():
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    qr.make_image(fill_color="#111827", back_color="white").save(output / filename)
    print(f"{filename}: {data}")
