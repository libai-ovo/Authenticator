import Vue from "vue";
import ImportView from "./components/Import.vue";
import CommonComponents from "./components/common/index";
import { loadI18nMessages } from "./store/i18n";

import { Encryption } from "./models/encryption";
import { EntryStorage } from "./models/storage";
import { getOTPAuthPerLineFromOPTAuthMigration } from "./models/migration";
export { decryptBackupData } from "./models/decryptBackup";

async function init() {
  // i18n
  Vue.prototype.i18n = await loadI18nMessages();

  // Load common components globally
  for (const component of CommonComponents) {
    Vue.component(component.name, component.component);
  }

  // Load entries to global
  const cachedSecrets = await getCachedSecrets();
  const encryption = new Encryption(
    cachedSecrets.cachedPassphrase,
    cachedSecrets.cachedKeyId
  );
  const entries = await EntryStorage.get();

  if (encryption.getEncryptionStatus()) {
    for (const entry of entries) {
      await entry.applyEncryption(encryption);
    }
  }

  Vue.prototype.$entries = entries;
  Vue.prototype.$encryption = encryption;

  const instance = new Vue({
    render: (h) => h(ImportView),
  }).$mount("#import");

  // Set title
  try {
    document.title = instance.i18n.extName;
  } catch (e) {
    console.error(e);
  }
}

init();

async function getCachedSecrets() {
  const { cachedPassphrase, cachedKeyId } = await chrome.storage.session.get();

  return { cachedPassphrase, cachedKeyId };
}

export async function getEntryDataFromOTPAuthPerLine(importCode: string) {
  const lines = importCode.split("\n");
  const exportData: { [hash: string]: RawOTPStorage } = {};
  let failedCount = 0;
  let succeededCount = 0;
  for (let item of lines) {
    item = item.trim();
    if (item.startsWith("otpauth-migration:")) {
      const migrationData = getOTPAuthPerLineFromOPTAuthMigration(item);
      for (const line of migrationData) {
        lines.push(line);
      }
      continue;
    }
    if (!item.startsWith("otpauth:")) {
      continue;
    }

    let uri = item.split("otpauth://")[1];
    let type = uri.substr(0, 4).toLowerCase();
    uri = uri.substr(5);
    let label = uri.split("?")[0];
    const parameterPart = uri.split("?")[1];
    if (!parameterPart) {
      failedCount++;
      continue;
    } else {
      let secret = "";
      let account: string | undefined;
      let issuer: string | undefined;
      let algorithm: string | undefined;
      let period: number | undefined;
      let digits: number | undefined;

      try {
        label = decodeURIComponent(label);
      } catch (error) {
        console.error(error);
      }
      if (label.indexOf(":") !== -1) {
        issuer = label.split(":")[0];
        account = label.split(":")[1];
      } else {
        account = label;
      }
      const parameters = parameterPart.split("&");
      parameters.forEach((item) => {
        const parameter = item.split("=");
        if (parameter[0].toLowerCase() === "secret") {
          secret = parameter[1];
        } else if (parameter[0].toLowerCase() === "issuer") {
          try {
            issuer = decodeURIComponent(parameter[1]);
          } catch {
            issuer = parameter[1];
          }
          issuer = issuer.replace(/\+/g, " ");
        } /* else if (parameter[0].toLowerCase() === "counter") {
          let counter = Number(parameter[1]);
          counter = isNaN(counter) || counter < 0 ? 0 : counter;
        } */ else if (
          parameter[0].toLowerCase() === "period"
        ) {
          period = Number(parameter[1]);
          period =
            isNaN(period) || period < 0 || period > 60 || 60 % period !== 0
              ? undefined
              : period;
        } else if (parameter[0].toLowerCase() === "digits") {
          digits = Number(parameter[1]);
          digits = isNaN(digits) ? 6 : digits;
        } else if (parameter[0].toLowerCase() === "algorithm") {
          algorithm = parameter[1];
        }
      });

      if (!secret) {
        failedCount++;
        continue;
      } else if (
        !/^[0-9a-f]+$/i.test(secret) &&
        !/^[2-7a-z]+=*$/i.test(secret)
      ) {
        failedCount++;
        continue;
      } else {
        const hash = crypto.randomUUID();
        if (
          !/^[2-7a-z]+=*$/i.test(secret) &&
          /^[0-9a-f]+$/i.test(secret) &&
          type === "totp"
        ) {
          type = "hex";
        } else if (
          !/^[2-7a-z]+=*$/i.test(secret) &&
          /^[0-9a-f]+$/i.test(secret) &&
          type === "hotp"
        ) {
          type = "hhex";
        }

        exportData[hash] = {
          account,
          hash,
          issuer,
          secret,
          type,
          encrypted: false,
          index: 0,
          counter: 0,
          pinned: false,
        };
        if (period) {
          exportData[hash].period = period;
        }
        if (digits) {
          exportData[hash].digits = digits;
        }
        if (algorithm) {
          exportData[hash].algorithm = algorithm;
        }

        succeededCount++;
      }
    }
  }

  return { exportData, failedCount, succeededCount };
}
