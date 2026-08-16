<template>
  <div>
    <div>
      <div v-show="backupToken">
        <div style="margin: 10px 0px 0px 20px; overflow-wrap: break-word">
          {{ i18n.account }} - {{ username }}
        </div>
      </div>
      <a-select-input
        v-show="!backupToken"
        :label="i18n.webdav_template"
        v-model="webdavTemplate"
        @change="onTemplateChange"
      >
        <option value="custom">{{ i18n.webdav_template_custom }}</option>
        <option value="nutstore">{{ i18n.webdav_template_nutstore }}</option>
      </a-select-input>
      <a-text-input
        v-show="!backupToken"
        :label="i18n.webdav_url"
        v-model="webdavUrl"
        placeholder="https://webdav.example.com"
      ></a-text-input>
      <a-text-input
        v-show="!backupToken"
        :label="i18n.webdav_path"
        v-model="webdavPath"
        placeholder="/backup"
      ></a-text-input>
      <a-text-input
        v-show="!backupToken"
        :label="i18n.username"
        v-model="webdavUsername"
      ></a-text-input>
      <a-text-input
        v-show="!backupToken"
        :label="i18n.password"
        type="password"
        v-model="webdavPassword"
      ></a-text-input>
      <a-button v-show="backupToken" @click="backupLogout()">
        {{ i18n.log_out }}
      </a-button>
      <a-button v-show="!backupToken" @click="saveCredentials()">
        {{ i18n.save }}
      </a-button>
      <a-button v-show="backupToken" @click="backupUpload()">
        {{ i18n.manual_webdav }}
      </a-button>
      <a-button
        v-show="backupToken && !getFilePassphrase"
        @click="backupRestore()"
      >
        {{ i18n.webdav_restore }}
      </a-button>
      <div v-show="getFilePassphrase">
        <p class="error_password">{{ i18n.passphrase_info }}</p>
        <a-text-input
          :label="i18n.phrase"
          type="password"
          @enter="readFilePassphrase = true"
          v-model="importFilePassphrase"
        />
        <a-button @click="readFilePassphrase = true">{{ i18n.ok }}</a-button>
      </div>
    </div>
  </div>
</template>
<script lang="ts">
import * as CryptoJS from "crypto-js";
import Vue from "vue";
import { WebDAV } from "../../models/backup";
import { decryptBackupData } from "../../models/decryptBackup";
import { Encryption } from "../../models/encryption";
import { UserSettings } from "../../models/settings";
import { EntryStorage } from "../../models/storage";

const service = "webdav";

// Built-in template: Jianguoyun (Nutstore) WebDAV. Users only need to enter
// their account email and app password.
const DEFAULT_WEBDAV_URL = "https://dav.jianguoyun.com/dav/";
const DEFAULT_WEBDAV_PATH = "/authenticator-sync";

export default Vue.extend({
  data: function () {
    return {
      username: this.i18n.loading,
      webdavTemplate: "custom",
      webdavUrl: "",
      webdavUsername: "",
      webdavPassword: "",
      webdavPath: "",
      getFilePassphrase: false,
      readFilePassphrase: false,
      importFilePassphrase: "",
    };
  },
  created() {
    UserSettings.updateItems();
    this.webdavUrl = UserSettings.items.webdavUrl || "";
    this.webdavUsername = UserSettings.items.webdavUsername || "";
    this.webdavPassword = UserSettings.items.webdavPassword || "";
    this.webdavPath = UserSettings.items.webdavPath || "";
    // Match the template selector to an already configured URL.
    if (this.webdavUrl.includes("dav.jianguoyun.com")) {
      this.webdavTemplate = "nutstore";
    }
  },
  computed: {
    backupToken: function () {
      return this.$store.state.backup.webdavToken;
    },
  },
  methods: {
    async saveCredentials() {
      if (!this.webdavUrl || !this.webdavUsername || !this.webdavPassword) {
        this.$store.commit(
          "notification/alert",
          this.i18n.webdav_missing_credentials
        );
        return;
      }

      // Save the form before requesting host permission: the permission
      // prompt closes the popup, which would otherwise discard the user's
      // input and force them to re-enter it.
      UserSettings.items.webdavUrl = this.webdavUrl;
      UserSettings.items.webdavUsername = this.webdavUsername;
      UserSettings.items.webdavPassword = this.webdavPassword;
      UserSettings.items.webdavPath = this.webdavPath;
      await UserSettings.commitItems();

      // Request permission to access the WebDAV server domain. This must be
      // called from a user gesture (the Save button click) and lets requests
      // to the server bypass CORS restrictions.
      if (chrome.permissions && chrome.permissions.request) {
        try {
          const origin = new URL(this.webdavUrl).origin + "/*";
          const granted = await new Promise<boolean>((resolve) => {
            chrome.permissions.request({ origins: [origin] }, (result) => {
              resolve(Boolean(result));
            });
          });
          if (!granted) {
            // The user declined: roll back the previously saved credentials.
            UserSettings.items.webdavUrl = undefined;
            UserSettings.items.webdavUsername = undefined;
            UserSettings.items.webdavPassword = undefined;
            UserSettings.items.webdavPath = undefined;
            await UserSettings.commitItems();
            this.$store.commit(
              "notification/alert",
              this.i18n.webdav_permission_denied
            );
            return;
          }
        } catch (e) {
          console.error("Failed to request WebDAV host permission:", e);
        }
      }

      // Test the connection
      const webdav = new WebDAV();
      const result = await webdav.getUser();
      if (result.startsWith("Error")) {
        this.$store.commit("notification/alert", result);
        UserSettings.items.webdavUsername = undefined;
        UserSettings.items.webdavPassword = undefined;
        UserSettings.commitItems();
        this.$store.commit("backup/setToken", { service, value: false });
      } else {
        this.username = result;
        this.$store.commit("backup/setToken", { service, value: true });
        this.$store.commit("notification/alert", this.i18n.updateSuccess);
      }
    },
    backupLogout() {
      UserSettings.removeItem(`${service}Username`);
      UserSettings.removeItem(`${service}Password`);
      UserSettings.removeItem(`${service}Url`);
      UserSettings.removeItem(`${service}Path`);
      this.$store.commit("backup/setToken", { service, value: false });
      this.$store.commit("style/hideInfo");
      this.webdavTemplate = "custom";
      this.webdavUrl = "";
      this.webdavUsername = "";
      this.webdavPassword = "";
      this.webdavPath = "";
    },
    async onTemplateChange() {
      if (this.webdavTemplate !== "nutstore") {
        return;
      }
      // Fill in the Jianguoyun template.
      this.webdavUrl = DEFAULT_WEBDAV_URL;
      this.webdavPath = DEFAULT_WEBDAV_PATH;
      // Request host permission right away while this is still a user
      // gesture, so saving later won't need another prompt.
      if (chrome.permissions && chrome.permissions.request) {
        try {
          const granted = await new Promise<boolean>((resolve) => {
            chrome.permissions.request(
              { origins: ["https://dav.jianguoyun.com/*"] },
              (result) => {
                resolve(Boolean(result));
              }
            );
          });
          if (!granted) {
            this.$store.commit(
              "notification/alert",
              this.i18n.webdav_permission_denied
            );
          }
        } catch (e) {
          console.error("Failed to request Jianguoyun host permission:", e);
        }
      }
    },
    async backupUpload() {
      const webdav = new WebDAV();
      const response = await webdav.upload(
        this.$store.state.accounts.encryption.get(
          this.$store.state.accounts.defaultEncryption
        )
      );
      if (response === true) {
        this.$store.commit("notification/alert", this.i18n.updateSuccess);
      } else if (UserSettings.items.webdavRevoked === true) {
        this.$store.commit(
          "notification/alert",
          chrome.i18n.getMessage("token_revoked", ["WebDAV"])
        );
        UserSettings.removeItem("webdavUsername");
        UserSettings.removeItem("webdavPassword");
        this.$store.commit("backup/setToken", { service, value: false });
      } else {
        this.$store.commit("notification/alert", this.i18n.updateFailure);
      }
    },
    async backupRestore() {
      const webdav = new WebDAV();
      const fileData = await webdav.download();
      if (fileData === null) {
        if (UserSettings.items.webdavRevoked === true) {
          this.$store.commit(
            "notification/alert",
            chrome.i18n.getMessage("token_revoked", ["WebDAV"])
          );
          UserSettings.removeItem("webdavUsername");
          UserSettings.removeItem("webdavPassword");
          this.$store.commit("backup/setToken", { service, value: false });
        } else {
          this.$store.commit("notification/alert", this.i18n.updateFailure);
        }
        return;
      }

      let importData: {
        // @ts-ignore
        key?: { enc: string; hash: string };
        [hash: string]: RawOTPStorage | Key;
        // Bug #557, uploaded backups were missing `key`
        // @ts-ignore
        enc?: string;
        // @ts-ignore
        hash?: string;
      } = {};
      try {
        importData = JSON.parse(fileData);
      } catch (e) {
        console.warn(e);
        this.$store.commit("notification/alert", this.i18n.migration_fail);
        return;
      }

      let key: { enc: string } | null = null;

      if (importData.hasOwnProperty("key")) {
        if (importData.key) {
          key = importData.key;
        }
        delete importData.key;
      } else if (importData.enc && importData.hash) {
        key = { enc: importData.enc };
        delete importData.hash;
        delete importData.enc;
      }

      let decryptedFileData: { [hash: string]: RawOTPStorage } = {};
      for (const hash in importData) {
        const possibleEntry = importData[hash];
        if (possibleEntry.dataType === "Key") {
          // don't try to import keys as an OTPEntry
          continue;
        }

        if (possibleEntry.keyId || possibleEntry.encrypted) {
          try {
            // WebDAV backups are encrypted with the WebDAV password, try it
            // first so no extra passphrase is needed.
            const webdavPassword = UserSettings.items.webdavPassword || null;
            if (webdavPassword) {
              decryptedFileData = await decryptBackupData(
                importData,
                webdavPassword
              );
            }

            if (!Object.keys(decryptedFileData).length) {
              // Older backups are encrypted with the local passphrase, ask
              // the user for it.
              const oldPassphrase:
                | string
                | null = await this.getOldPassphrase();

              if (key) {
                // v2 encryption
                decryptedFileData = await decryptBackupData(
                  importData,
                  CryptoJS.AES.decrypt(key.enc, oldPassphrase).toString()
                );
              } else {
                // v3 and v1 encryption
                decryptedFileData = await decryptBackupData(
                  importData,
                  oldPassphrase
                );
              }
            }

            break;
          } catch {
            break;
          }
        } else {
          decryptedFileData[hash] = possibleEntry;
        }
      }

      if (Object.keys(decryptedFileData).length) {
        await EntryStorage.import(
          this.$store.state.accounts.encryption.get(
            this.$store.state.accounts.defaultEncryption
          ) || new Encryption("", ""),
          decryptedFileData
        );
        await this.$store.dispatch("accounts/updateEntries");
        this.$store.commit("notification/alert", this.i18n.updateSuccess);
      } else {
        this.$store.commit("notification/alert", this.i18n.migration_fail);
        this.getFilePassphrase = false;
        this.importFilePassphrase = "";
      }
    },
    async getOldPassphrase() {
      this.getFilePassphrase = true;
      while (true) {
        if (this.readFilePassphrase) {
          if (this.importFilePassphrase) {
            this.readFilePassphrase = false;
            break;
          } else {
            this.readFilePassphrase = false;
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      return this.importFilePassphrase;
    },
    async getUser() {
      const webdav = new WebDAV();
      return await webdav.getUser();
    },
  },
  mounted: async function () {
    if (this.backupToken) {
      this.username = await this.getUser();
    }
  },
});
</script>
