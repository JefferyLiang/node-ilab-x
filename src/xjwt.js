const crypto = require("crypto");
const AES_KEY_LENGTH = 44;
const BASE64_SIG_LENGTH = 44;

function BufferConcat(buf1, buf2) {
  let buf = new Buffer.alloc(buf1.length + buf2.length);
  buf1.copy(buf, 0);
  buf2.copy(buf, buf1.length);
  return buf;
}

class XJWT {
  constructor(aesKey, secretKey) {
    this.aesKey = aesKey;
    this.secretKey = secretKey;
    if (this.aesKey.length != AES_KEY_LENGTH) {
      throw new IllegalArgumentException("Aes key length must be 44!");
    }
  }

  get token() {
    return this._token || null;
  }

  get signature() {
    return this._signature;
  }

  setToken(token) {
    let tokenArr = token.split(".");
    if (tokenArr.length !== 3) {
      throw new Error("Invalid JWT Length!");
    }

    const hmac = crypto.createHmac("sha256", this.secretKey);
    const i = token.length - BASE64_SIG_LENGTH - 1;
    if (i < 0 || token.charAt(i) !== ".") {
      throw new Error("Invalid JWT!");
    }
    hmac.update(`${tokenArr[0]}.${tokenArr[1]}`);
    const _sig = hmac.digest("base64");
    if (_sig !== tokenArr[2]) {
      throw new Error("Invalid JWT Signature");
    }

    this._token = token;
    this._header = tokenArr[0];
    this._payload = tokenArr[1];
    this._signature = tokenArr[2];
  }

  getHeader() {
    let _decoder = new Buffer.from(this._header, "base64").toString("hex");
    let expiry = _decoder.slice(0, 16).toString("utf8");
    let type = _decoder.slice(16, 18).toString("utf8");
    let issuer = _decoder.slice(18, 18 + 16).toString("utf8");
    return {
      expiry: parseInt(expiry, 16),
      type: parseInt(type, 2),
      issuerId: parseInt(issuer, 16)
    };
  }

  getPayload() {
    let keyBuffer = new Buffer.from(this.aesKey, "base64");
    let iv = keyBuffer.slice(0, 16);
    // encrypt data
    let cipher = crypto.createDecipheriv("aes-256-cbc", keyBuffer, iv);
    let decrepted =
      cipher.update(this._payload, "base64", "utf8") + cipher.final("utf8");
    decrepted = decrepted.slice();
    return decrepted.slice(7).toString();
  }

  decode() {
    if (!this.token) return null;
    return {
      header: this.getHeader(),
      signature: this.signature,
      payload: this.getPayload()
    };
  }

  signHeader(expiry, type, issuerId) {
    let expiryStr = expiry.toString(16);
    if (expiryStr.length !== 16) expiryStr = expiryStr.padStart(16, "0");
    let typeStr = type.toString(2);
    if (typeStr.length !== 2) typeStr = typeStr.padStart(2, "0");
    let issuerIdStr = issuerId.toString(16);
    if (issuerIdStr.length !== 16) issuerIdStr = issuerIdStr.padStart(16, "0");
    return new Buffer.from(expiryStr + typeStr + issuerIdStr, "hex").toString(
      "base64"
    );
  }

  signPayload(payload) {
    let payloadBuffer = new Buffer.from(payload, "utf8");
    let dirtyBuffer = new Buffer.from("0000000", "utf8");
    let buf = BufferConcat(dirtyBuffer, payloadBuffer);
    let keyBuffer = new Buffer.from(this.aesKey, "base64");
    let iv = keyBuffer.slice(0, 16);
    let cipher = crypto.createCipheriv("aes-256-cbc", keyBuffer, iv);
    cipher.setAutoPadding(true);
    let crypted = cipher.update(buf.toString("hex"), "hex", "base64");
    crypted += cipher.final("base64");
    return crypted;
  }

  signSignature(header, payload) {
    let cipher = crypto.createHmac("sha256", this.secretKey);
    let encrypted = cipher.update(`${header}.${payload}`);
    return encrypted.digest("base64");
  }

  sign(type, payload, issuerId) {
    // header
    let expiry = +new Date() + 1000 * 1000;
    let header = this.signHeader(expiry, type, issuerId);
    let _payload = this.signPayload(payload);
    let signature = this.signSignature(header, _payload);
    return `${header}.${_payload}.${signature}`;
  }
}

module.exports = XJWT;
