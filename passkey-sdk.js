// passkey-sdk.js — ES256 version
const PasskeySDK = (() => {
  const BASE_URL = "https://passkey-backend-xht7.onrender.com";

  // --- helpers ---
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

  // base64url -> ArrayBuffer
  function base64UrlToBuffer(base64urlString) {
    const padding = "=".repeat((4 - (base64urlString.length % 4)) % 4);
    const base64 = base64urlString.replace(/-/g, "+").replace(/_/g, "/") + padding;
    const str = atob(base64);
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0; i < str.length; i++) bufView[i] = str.charCodeAt(i);
    return buf;
  }

  // --- minimal CBOR decoder (enough for COSE keys) ---
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
      if (ai === 27) {
        const hi = readUint(4), lo = readUint(4);
        return hi * 2 ** 32 + lo;
      }
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

  // --- extract EC (P-256) public key from attestationObject ---
  async function extractECPublicKey(attestationBuffer) {
    // attestationBuffer: ArrayBuffer or Uint8Array
    const attObj = decodeCBOR(attestationBuffer);
    const authData = attObj.authData;
    if (!authData) throw new Error("missing authData in attestationObject");

    // authData is Uint8Array
    let ptr = 0;
    ptr += 32; // rpIdHash
    ptr += 1;  // flags
    ptr += 4;  // signCount

    // attestedCredentialData: aaguid(16) + credIdLen(2) + credId + credentialPublicKey (CBOR)
    ptr += 16; // aaguid
    const credIdLen = (authData[ptr] << 8) | authData[ptr + 1];
    ptr += 2;
    ptr += credIdLen;
    const coseKeyBytes = authData.slice(ptr); // rest is CBOR COSE key
    const coseKey = decodeCBOR(coseKeyBytes.buffer);

    // COSE: 1 => kty, 3 => alg, -1 => crv, -2 => x, -3 => y
    if (coseKey[1] !== 2) { // 2 == EC2
      throw new Error("COSE key is not EC2");
    }
    const crv = coseKey[-1]; // typically 1 => P-256
    const x = coseKey[-2];
    const y = coseKey[-3];
    if (!x || !y) throw new Error("COSE EC key missing x/y");

    // build uncompressed point 0x04 || x || y
    const pubKeyRaw = new Uint8Array(1 + x.length + y.length);
    pubKeyRaw[0] = 0x04;
    pubKeyRaw.set(x, 1);
    pubKeyRaw.set(y, 1 + x.length);

    // import raw EC public key and export SPKI (PEM)
    const namedCurve = (crv === 1) ? "P-256" : (crv === 2 ? "P-384" : (crv === 3 ? "P-521" : null));
    if (!namedCurve) throw new Error("Unsupported EC curve: " + crv);

    const key = await crypto.subtle.importKey(
      "raw",
      pubKeyRaw.buffer,
      { name: "ECDSA", namedCurve },
      true,
      ["verify"]
    );
    const spki = await crypto.subtle.exportKey("spki", key);
    return pemFromSpki(spki);
  }

  // --- main register() : uses register-challenge endpoint and requests ES256 ---
  async function register(id) {
    if (!id) throw new Error("id is required");

    // get options from server
    const challengeRes = await fetch(`${BASE_URL}/api/register-challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    if (!challengeRes.ok) throw new Error("Failed to get register challenge from server");
    const options = await challengeRes.json();
    const publicKey = options.publicKey;

    // convert challenge and user.id to required types
    publicKey.challenge = base64UrlToBuffer(publicKey.challenge);
    // ensure rp.id is compatible — server should have set rp.id appropriately

    // user.id must be ArrayBuffer — server sent base64url, but we will use provided id
    // many servers set user.id as base64url; if not, encode client-side:
    if (!publicKey.user || !publicKey.user.id) {
      publicKey.user = publicKey.user || {};
      publicKey.user.id = new TextEncoder().encode(id);
      publicKey.user.name = id;
      publicKey.user.displayName = id;
    } else {
      // if server-provided, it might be base64url string — try to convert:
      if (typeof publicKey.user.id === "string") {
        try {
          publicKey.user.id = base64UrlToBuffer(publicKey.user.id);
        } catch (e) {
          publicKey.user.id = new TextEncoder().encode(id);
        }
      }
    }

    // enforce ES256 as first option
    publicKey.pubKeyCredParams = [{ type: "public-key", alg: -7 }];

    // ask for platform authenticator if desired (server may already set)
    publicKey.authenticatorSelection = publicKey.authenticatorSelection || {};
    // keep existing authenticatorAttachment if server provided; otherwise prefer platform:
    // publicKey.authenticatorSelection.authenticatorAttachment = "platform";

    // create credential
    const cred = await navigator.credentials.create({ publicKey });
    if (!cred) throw new Error("credential creation failed");

    // extract attestation and EC public key PEM
    const attestationBuffer = cred.response.attestationObject;
    const publicKeyPem = await extractECPublicKey(attestationBuffer);

    // send to server
    const saveRes = await fetch(`${BASE_URL}/api/save-key`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, public_key: publicKeyPem })
    });
    if (!saveRes.ok) {
      const j = await saveRes.json().catch(()=>({}));
      throw new Error(j.error || "Failed to save public key");
    }

    return { success: true, publicKeyPem, credentialId: bufferToBase64(cred.rawId) };
  }

  return { register, extractECPublicKey };
})();

if (typeof window !== "undefined") window.PasskeySDK = PasskeySDK;
