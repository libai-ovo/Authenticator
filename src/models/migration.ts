import * as CryptoJS from "crypto-js";

function byteArray2Base32(bytes: number[]) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const len = bytes.length;
  let result = "";
  let high = 0,
    low = 0,
    sh = 0,
    hasDataInLow = false;
  for (let i = 0; i < len; i += 5) {
    hasDataInLow = true;
    high = 0xf8 & bytes[i];
    result += chars.charAt(high >> 3);
    low = 0x07 & bytes[i];
    sh = 2;

    if (i + 1 < len) {
      high = 0xc0 & bytes[i + 1];
      result += chars.charAt((low << 2) + (high >> 6));
      result += chars.charAt((0x3e & bytes[i + 1]) >> 1);
      low = bytes[i + 1] & 0x01;
      sh = 4;
    }

    if (i + 2 < len) {
      high = 0xf0 & bytes[i + 2];
      result += chars.charAt((low << 4) + (high >> 4));
      low = 0x0f & bytes[i + 2];
      sh = 1;
    }

    if (i + 3 < len) {
      high = 0x80 & bytes[i + 3];
      result += chars.charAt((low << 1) + (high >> 7));
      result += chars.charAt((0x7c & bytes[i + 3]) >> 2);
      low = 0x03 & bytes[i + 3];
      sh = 3;
    }

    if (i + 4 < len) {
      hasDataInLow = false;
      high = 0xe0 & bytes[i + 4];
      result += chars.charAt((low << 3) + (high >> 5));
      result += chars.charAt(0x1f & bytes[i + 4]);
      low = 0;
      sh = 0;
    }
  }

  if (hasDataInLow) {
    result += chars.charAt(low << sh);
  }

  const padlen = 8 - (result.length % 8);
  return result + (padlen < 8 ? Array(padlen + 1).join("=") : "");
}

function wordArrayToByteArray(wordArray: CryptoJS.lib.WordArray) {
  const byteArray: number[] = [];
  for (let i = 0; i < wordArray.words.length; ++i) {
    const word = wordArray.words[i];
    for (let j = 3; j >= 0; --j) {
      byteArray.push((word >> (8 * j)) & 0xff);
    }
  }
  byteArray.length = wordArray.sigBytes;
  return byteArray;
}

function byteArray2String(bytes: number[]) {
  return String.fromCharCode.apply(null, bytes);
}

function readVarint(bytes: number[], offset: number) {
  let value = 0;
  let shift = 0;
  let current = offset;
  // varint 解码：按字节循环，内部根据 continuation bit 决定是否 break
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const byte = bytes[current++];
    if (byte === undefined) {
      throw new Error("Invalid varint: unexpected end of data");
    }
    value += (byte & 0x7f) * Math.pow(2, shift);
    if ((byte & 0x80) === 0) {
      break;
    }
    shift += 7;
  }
  return { value, newOffset: current };
}

interface OtpParameters {
  secret?: number[];
  name?: string;
  issuer?: string;
  algorithm?: number;
  digits?: number;
  type?: number;
  counter?: number;
}

function parseOtpParameters(bytes: number[]): OtpParameters {
  const params: OtpParameters = {};
  let offset = 0;
  while (offset < bytes.length) {
    const { value: tag, newOffset: afterTag } = readVarint(bytes, offset);
    offset = afterTag;
    const fieldNumber = tag >>> 3;
    const wireType = tag & 7;
    if (wireType === 0) {
      const { value, newOffset } = readVarint(bytes, offset);
      offset = newOffset;
      if (fieldNumber === 4) {
        params.algorithm = value;
      } else if (fieldNumber === 5) {
        params.digits = value;
      } else if (fieldNumber === 6) {
        params.type = value;
      } else if (fieldNumber === 7) {
        params.counter = value;
      }
    } else if (wireType === 2) {
      const { value: length, newOffset } = readVarint(bytes, offset);
      offset = newOffset;
      const fieldBytes = bytes.slice(offset, offset + length);
      offset += length;
      if (fieldNumber === 1) {
        params.secret = fieldBytes;
      } else if (fieldNumber === 2) {
        params.name = byteArray2String(fieldBytes);
      } else if (fieldNumber === 3) {
        params.issuer = byteArray2String(fieldBytes);
      }
    } else if (wireType === 1) {
      offset += 8;
    } else if (wireType === 5) {
      offset += 4;
    } else {
      throw new Error(`Unsupported wire type ${wireType}`);
    }
  }
  return params;
}

function parseMigrationPayload(bytes: number[]): OtpParameters[] {
  const otpParameters: OtpParameters[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    const { value: tag, newOffset: afterTag } = readVarint(bytes, offset);
    offset = afterTag;
    const fieldNumber = tag >>> 3;
    const wireType = tag & 7;
    if (fieldNumber === 1 && wireType === 2) {
      const { value: length, newOffset } = readVarint(bytes, offset);
      offset = newOffset;
      otpParameters.push(
        parseOtpParameters(bytes.slice(offset, offset + length))
      );
      offset += length;
    } else if (wireType === 0) {
      const { newOffset } = readVarint(bytes, offset);
      offset = newOffset;
    } else if (wireType === 1) {
      offset += 8;
    } else if (wireType === 5) {
      offset += 4;
    } else {
      throw new Error(`Unsupported wire type ${wireType}`);
    }
  }
  return otpParameters;
}

export function getOTPAuthPerLineFromOPTAuthMigration(migrationUri: string) {
  if (!migrationUri.startsWith("otpauth-migration:")) {
    return [];
  }

  const base64Data = decodeURIComponent(migrationUri.split("data=")[1]);
  const wordArrayData = CryptoJS.enc.Base64.parse(base64Data);
  const byteData = wordArrayToByteArray(wordArrayData);
  const lines: string[] = [];
  for (const params of parseMigrationPayload(byteData)) {
    const secret = byteArray2Base32(params.secret || []);
    const account = params.name || "";
    const issuer = params.issuer || "";
    const algorithm =
      ["SHA1", "SHA1", "SHA256", "SHA512", "MD5"][params.algorithm || 0] ||
      "SHA1";
    const digits = [6, 6, 8][params.digits || 0] || 6;
    const type = ["totp", "hotp", "totp"][params.type || 0] || "totp";
    let line = `otpauth://${type}/${account}?secret=${secret}&issuer=${issuer}&algorithm=${algorithm}&digits=${digits}`;
    if (type === "hotp") {
      line += `&counter=${params.counter || 1}`;
    }
    lines.push(line);
  }
  return lines;
}
