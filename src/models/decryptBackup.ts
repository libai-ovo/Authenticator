import * as CryptoJS from "crypto-js";

async function findAndUnlockKey(
  importData: { [key: string]: OTPStorage | Key },
  keyId: string,
  password: string
): Promise<string | null> {
  if (!(keyId in importData)) {
    return null;
  }

  const key = importData[keyId];
  if (key.dataType !== "Key" || key.id !== keyId) {
    return null;
  }

  const rawHash = await new Promise((resolve: (value: string) => void) => {
    const iframe = document.getElementById("argon-sandbox");
    const message = {
      action: "hash",
      value: password,
      salt: key.salt,
    };
    if (iframe) {
      window.addEventListener("message", (response) => {
        resolve(response.data.response);
      });
      // @ts-expect-error bad typings
      iframe.contentWindow.postMessage(message, "*");
    }
  });

  // https://passlib.readthedocs.io/en/stable/lib/passlib.hash.argon2.html#format-algorithm
  const possibleHash = rawHash.split("$")[5];
  if (!possibleHash) {
    throw new Error("argon2 did not return a hash!");
  }

  // verify user password by comparing their password hash with the
  // hash of their password's hash
  const isCorrectPassword = await new Promise(
    (resolve: (value: string) => void) => {
      const iframe = document.getElementById("argon-sandbox");
      const message = {
        action: "verify",
        value: possibleHash,
        hash: key.hash,
      };
      if (iframe) {
        window.addEventListener("message", (response) => {
          resolve(response.data.response);
        });
        // @ts-expect-error bad typings
        iframe.contentWindow.postMessage(message, "*");
      }
    }
  );

  if (!isCorrectPassword) {
    return null;
  }

  return possibleHash;
}

export async function decryptBackupData(
  backupData: { [hash: string]: OTPStorage | Key },
  passphrase: string | null
) {
  const decryptedBackupData: { [hash: string]: RawOTPStorage } = {};
  const keys: Map<string, string | null> = new Map();
  for (const hash in backupData) {
    const unknownStorageItem = backupData[hash];
    if (
      typeof unknownStorageItem !== "object" ||
      unknownStorageItem.dataType === "Key"
    ) {
      continue;
    }
    let storageItem: RawOTPStorage;
    if (unknownStorageItem.dataType === "EncOTPStorage") {
      if (!passphrase) {
        continue;
      }

      if (!keys.has(unknownStorageItem.keyId)) {
        keys.set(
          unknownStorageItem.keyId,
          await findAndUnlockKey(
            backupData,
            unknownStorageItem.keyId,
            passphrase
          )
        );
      }
      const decryptKey = keys.get(unknownStorageItem.keyId);
      if (!decryptKey) {
        // wrong password for key
        continue;
      }

      storageItem = {
        ...unknownStorageItem,
        ...JSON.parse(
          CryptoJS.AES.decrypt(unknownStorageItem.data, decryptKey).toString(
            CryptoJS.enc.Utf8
          )
        ),
        encrypted: false,
      };
    } else {
      storageItem = unknownStorageItem;
    }
    if (!storageItem.secret) {
      continue;
    }
    if (storageItem.encrypted && !passphrase) {
      continue;
    }
    if (storageItem.encrypted && passphrase) {
      try {
        storageItem.secret = CryptoJS.AES.decrypt(
          storageItem.secret,
          passphrase
        ).toString(CryptoJS.enc.Utf8);
        storageItem.encrypted = false;
      } catch (error) {
        continue;
      }
    }
    // storageItem.secret may be empty after decrypt with wrong
    // passphrase
    if (!storageItem.secret) {
      continue;
    }
    decryptedBackupData[hash] = storageItem;
  }
  return decryptedBackupData;
}
