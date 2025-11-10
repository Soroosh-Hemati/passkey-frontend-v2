// passkey-sdk.js (Register - pure RSA key generation, no challenge)
const PasskeySDK = (() => {
  const BASE_URL = "https://passkey-backend-xht7.onrender.com";

  // تبدیل ArrayBuffer به Base64
  function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  // تبدیل کلید عمومی به PEM
  function toPEM(spkiBuffer) {
    const b64 = bufferToBase64(spkiBuffer);
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----`;
  }

  // ذخیره کلید خصوصی در IndexedDB (یا localStorage)
  async function storePrivateKey(id, privateKey) {
    const exported = await crypto.subtle.exportKey("pkcs8", privateKey);
    const base64 = bufferToBase64(exported);
    localStorage.setItem(`privateKey_${id}`, base64);
  }

  // ثبت‌نام: ساخت کلید RSA و ذخیره در سرور
  async function register(id) {
    if (!id) throw new Error("id الزامی است");

    // ساخت کلید RSA (RSA-SHA256)
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: "SHA-256",
      },
      true, // extractable = true
      ["sign", "verify"]
    );

    // استخراج کلید عمومی (SPKI)
    const publicKeyBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyPEM = toPEM(publicKeyBuffer);

    // ارسال کلید عمومی به سرور
    const resp = await fetch(`${BASE_URL}/api/save-key`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, public_key: publicKeyPEM }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.error || "خطا در ارسال داده به سرور");
    }

    // ذخیره امن کلید خصوصی در دستگاه
    await storePrivateKey(id, keyPair.privateKey);

    return { success: true, publicKey: publicKeyPEM };
  }

  return { register };
})();

if (typeof window !== "undefined") window.PasskeySDK = PasskeySDK;
