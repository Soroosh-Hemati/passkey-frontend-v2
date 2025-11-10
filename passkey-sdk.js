// passkey-sdk.js (RSA-SHA256 with backend URL)
const PasskeySDK = (() => {
  const BASE_URL = "https://passkey-backend-xht7.onrender.com";

  function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function pemFromSpki(spkiBuffer) {
    const b64 = bufferToBase64(spkiBuffer);
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----`;
  }

  // --- minimal CBOR decoder ---
  function decodeCBOR(buffer) {
    const bytes = new Uint8Array(buffer);
    let offset = 0;
    const textDecoder = new TextDecoder();

    function readUint(len) {
      let val = 0;
      for (let i = 0; i < len; i++) val = (val << 8) | bytes[offset++];
      return val >>> 0;
    }

    function readLength(ai) {
      if (ai < 24) return ai;
      if (ai === 24) return readUint(1);
      if (ai === 25) return readUint(2);
      if (ai === 26) return readUint(4);
      if (ai === 27) {
        const hi = readUint(4), lo = readUint(4);
        return hi * 2 ** 32 + lo;
      }
      throw new Error("unsupported length info");
    }

    function parseItem() {
      if (offset >= bytes.length) throw new Error("CBOR: unexpected end");
      const initial = bytes[offset++];
      const major = initial >> 5;
      const ai = initial & 0x1f;

      if (major === 0) return readLength(ai);
      if (major === 1) return -1 - readLength(ai);
      if (major === 2) {
        const len = readLength(ai);
        const start = offset;
        offset += len;
        return bytes.slice(start, start + len);
      }
      if (major === 3) {
        const len = readLength(ai);
        const start = offset;
        offset += len;
        return textDecoder.decode(bytes.slice(start, start + len));
      }
      if (major === 4) {
        const len = readLength(ai);
        const arr = [];
        for (let i = 0; i < len; i++) arr.push(parseItem());
        return arr;
      }
      if (major === 5) {
        const len = readLength(ai);
        const obj = {};
        for (let i = 0; i < len; i++) {
          const k = parseItem();
          const v = parseItem();
          obj[k] = v;
        }
        return obj;
      }
      if (major === 6) {
        readLength(ai);
        return parseItem();
      }
      if (major === 7) {
        if (ai === 20) return false;
        if (ai === 21) return true;
        if (ai === 22) return null;
        if (ai === 23) return undefined;
      }
      throw new Error("unsupported CBOR major type: " + major);
    }

    return parseItem();
  }

  // --- extract RSA public key ---
  async function extractRSAPublicKey(attestationBuffer) {
    const attObj = decodeCBOR(attestationBuffer);
    const authData = attObj.authData;
    if (!authData) throw new Error("missing authData");

    let ptr = 0;
    ptr += 32; // rpIdHash
    ptr += 1;  // flags
    ptr += 4;  // signCount
    ptr += 16; // aaguid
    const credIdLen = (authData[ptr] << 8) | authData[ptr + 1];
    ptr += 2;
    ptr += credIdLen;
    const coseKeyBytes = authData.slice(ptr);
    const coseKey = decodeCBOR(coseKeyBytes.buffer);

    if (coseKey[1] !== 3) throw new Error("Not RSA key");
    const n = coseKey[-1];
    const e = coseKey[-2];
    if (!n || !e) throw new Error("missing RSA components");

    const jwk = {
      kty: "RSA",
      n: bufferToBase64(n).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""),
      e: bufferToBase64(e).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""),
      alg: "RS256",
      ext: true,
    };

    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true,
      ["verify"]
    );
    const spki = await crypto.subtle.exportKey("spki", key);
    return pemFromSpki(spki);
  }

  // --- main register ---
  async function register(id) {
    if (!id) throw new Error("id الزامی است");

    const publicKey = {
      rp: { name: "Passkey Demo" },
      user: {
        id: new TextEncoder().encode(id),
        name: id,
        displayName: id
      },
      pubKeyCredParams: [{ type: "public-key", alg: -257 }], // RSA-SHA256
      timeout: 60000,
      attestation: "direct",
      authenticatorSelection: { userVerification: "preferred" },
    };

    const cred = await navigator.credentials.create({ publicKey });
    if (!cred) throw new Error("credential creation failed");

    const attestationBuffer = cred.response.attestationObject;
    const publicKeyPem = await extractRSAPublicKey(attestationBuffer);

    const resp = await fetch(`${BASE_URL}/api/save-key`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, public_key: publicKeyPem })
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(err.error || "خطا در ارتباط با سرور");
    }

    return { success: true, publicKeyPem };
  }

  return { register };
})();
if (typeof window !== "undefined") window.PasskeySDK = PasskeySDK;
