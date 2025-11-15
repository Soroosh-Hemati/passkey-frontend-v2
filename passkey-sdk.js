// passkey-sdk.js (dual: ES256 + RSA(-257))
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

  function base64UrlToBuffer(base64urlString) {
    const padding = "=".repeat((4 - (base64urlString.length % 4)) % 4);
    const base64 = base64urlString.replace(/-/g, "+").replace(/_/g, "/") + padding;
    const str = atob(base64);
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) bufView[i] = str.charCodeAt(i);
    return buf;
  }

  // minimal CBOR decoder (enough for COSE keys)
  function decodeCBOR(buffer) {
    const bytes = new Uint8Array(buffer);
    let offset = 0;
    const td = new TextDecoder();

    function readUint(len) {
      let v = 0;
      for (let i = 0; i < len; i++) v = (v << 8) | bytes[offset++];
      return v >>> 0;
    }
    function readLen(ai) {
      if (ai < 24) return ai;
      if (ai === 24) return readUint(1);
      if (ai === 25) return readUint(2);
      if (ai === 26) return readUint(4);
      if (ai === 27) { const hi = readUint(4), lo = readUint(4); return hi * 2 ** 32 + lo; }
      throw new Error("unsupported additional info: " + ai);
    }

    function parse() {
      if (offset >= bytes.length) throw new Error("CBOR: unexpected end");
      const initial = bytes[offset++];
      const major = initial >> 5;
      const ai = initial & 0x1f;

      if (major === 0) return readLen(ai);
      if (major === 1) return -1 - readLen(ai);
      if (major === 2) { const l = readLen(ai); const s = offset; offset += l; return bytes.slice(s, s + l); }
      if (major === 3) { const l = readLen(ai); const s = offset; offset += l; return td.decode(bytes.slice(s, s + l)); }
      if (major === 4) { const l = readLen(ai); const arr = []; for (let i=0;i<l;i++) arr.push(parse()); return arr; }
      if (major === 5) { const l = readLen(ai); const obj = {}; for (let i=0;i<l;i++){ const k = parse(); const v = parse(); obj[k] = v; } return obj; }
      if (major === 6) { readLen(ai); return parse(); }
      if (major === 7) { if (ai===20) return false; if (ai===21) return true; if (ai===22) return null; if (ai===23) return undefined; }
      throw new Error("unsupported CBOR major: " + major);
    }

    return parse();
  }

  // extract EC public key (P-256 etc)
  async function extractECPublicKeyFromAuthData(authData) {
    let ptr = 0;
    ptr += 32; ptr += 1; ptr += 4; // rpHash, flags, signCount
    ptr += 16; // aaguid
    const credIdLen = (authData[ptr] << 8) | authData[ptr + 1];
    ptr += 2;
    ptr += credIdLen;
    const coseKeyBytes = authData.slice(ptr);
    const coseKey = decodeCBOR(coseKeyBytes.buffer);

    if (coseKey[1] !== 2) throw new Error("COSE key is not EC2");
    const crv = coseKey[-1];
    const x = coseKey[-2];
    const y = coseKey[-3];
    const pubKeyRaw = new Uint8Array(1 + x.length + y.length);
    pubKeyRaw[0] = 0x04;
    pubKeyRaw.set(x, 1);
    pubKeyRaw.set(y, 1 + x.length);

    const namedCurve = (crv === 1) ? "P-256" : (crv === 2 ? "P-384" : (crv === 3 ? "P-521" : null));
    if (!namedCurve) throw new Error("Unsupported EC curve: " + crv);

    const key = await crypto.subtle.importKey("raw", pubKeyRaw.buffer, { name: "ECDSA", namedCurve }, true, ["verify"]);
    const spki = await crypto.subtle.exportKey("spki", key);
    return { pem: pemFromSpki(spki), alg: -7 };
  }

  // extract RSA public key from authData
  async function extractRSAPublicKeyFromAuthData(authData) {
    let ptr = 0;
    ptr += 32; ptr += 1; ptr += 4;
    ptr += 16;
    const credIdLen = (authData[ptr] << 8) | authData[ptr + 1];
    ptr += 2;
    ptr += credIdLen;
    const coseKeyBytes = authData.slice(ptr);
    const coseKey = decodeCBOR(coseKeyBytes.buffer);

    if (coseKey[1] !== 3) throw new Error("COSE key is not RSA");
    const n = coseKey[-1];
    const e = coseKey[-2];
    // JWK n,e base64url
    const jwk = {
      kty: "RSA",
      n: bufferToBase64(n).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""),
      e: bufferToBase64(e).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""),
      alg: "RS256",
      ext: true
    };
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, true, ["verify"]);
    const spki = await crypto.subtle.exportKey("spki", key);
    return { pem: pemFromSpki(spki), alg: -257 };
  }

  // generic extractor that inspects attestationObject and returns { pem, alg }
  async function extractPublicKeyFromAttestation(attestationBuffer) {
    // handle ArrayBuffer or Uint8Array
    const view = (attestationBuffer instanceof ArrayBuffer) ? new Uint8Array(attestationBuffer) : (attestationBuffer instanceof Uint8Array ? attestationBuffer : new Uint8Array(attestationBuffer.buffer));
    // decode CBOR attestationObject
    const attObj = decodeCBOR(view.buffer);
    if (!attObj || !attObj.authData) throw new Error("attestationObject parsing failed");
    const authData = attObj.authData; // Uint8Array
    // We need to inspect COSE key to see kty
    // easiest: decode COSE key as in extract functions: compute credIdLen etc then decode
    let ptr = 0;
    ptr += 32; ptr += 1; ptr += 4; ptr += 16;
    const credIdLen = (authData[ptr] << 8) | authData[ptr + 1];
    ptr += 2;
    ptr += credIdLen;
    const coseKeyBytes = authData.slice(ptr);
    const coseKey = decodeCBOR(coseKeyBytes.buffer);
    const kty = coseKey[1];
    if (kty === 2) {
      return await extractECPublicKeyFromAuthData(authData);
    } else if (kty === 3) {
      return await extractRSAPublicKeyFromAuthData(authData);
    } else {
      throw new Error("Unsupported COSE key type: " + kty);
    }
  }

  // main register()
  async function register(id) {
    if (!id) throw new Error("id الزامی است");

    // get challenge/options from server
    const challengeRes = await fetch(`${BASE_URL}/api/register-challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    if (!challengeRes.ok) throw new Error("دریافت challenge از سرور شکست خورد");
    const options = await challengeRes.json();
    const publicKey = options.publicKey;

    // convert challenge and user.id
    publicKey.challenge = base64UrlToBuffer(publicKey.challenge);
    if (!publicKey.user || !publicKey.user.id) {
      publicKey.user = { id: new TextEncoder().encode(id), name: id, displayName: id };
    } else {
      if (typeof publicKey.user.id === "string") {
        publicKey.user.id = base64UrlToBuffer(publicKey.user.id);
      }
    }

    // ensure both algs present (prefer server list but enforce ES256 first)
    publicKey.pubKeyCredParams = [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
    ];

    const cred = await navigator.credentials.create({ publicKey });
    if (!cred) throw new Error("ساخت credential شکست خورد");

    const attestation = cred.response.attestationObject;
    const attestationBuffer = (attestation instanceof ArrayBuffer) ? attestation : attestation.buffer || attestation;
    const keyInfo = await extractPublicKeyFromAttestation(attestationBuffer);

    // send public key and credential id to server
    const credentialIdB64 = bufferToBase64(cred.rawId);
    const resp = await fetch(`${BASE_URL}/api/save-key`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, public_key: keyInfo.pem, credential_id: credentialIdB64 })
    });
    if (!resp.ok) {
      const j = await resp.json().catch(()=>({}));
      throw new Error(j.error || "خطا در ذخیره public key در سرور");
    }

    return { success: true, publicKeyPem: keyInfo.pem, alg: keyInfo.alg, credentialId: credentialIdB64 };
  }

  return { register, extractPublicKeyFromAttestation };
})();

if (typeof window !== "undefined") window.PasskeySDK = PasskeySDK;
