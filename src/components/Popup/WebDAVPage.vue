<template>
  <div>
    <div>
      <div class="text warning" v-show="!isEncrypted || !defaultEncryption">
        {{ i18n.webdav_risk }}
      </div>
      <div v-show="backupToken">
        <div style="margin: 10px 0px 0px 20px; overflow-wrap: break-word">
          {{ i18n.account }} - {{ username }}
        </div>
      </div>
      <a-input
        v-show="!backupToken"
        :label="i18n.webdav_url"
        v-model="webdavUrl"
        placeholder="https://webdav.example.com"
      ></a-input>
      <a-input
        v-show="!backupToken"
        :label="i18n.username"
        v-model="webdavUsername"
      ></a-input>
      <a-input
        v-show="!backupToken"
        :label="i18n.password"
        type="password"
        v-model="webdavPassword"
      ></a-input>
      <a-select-input
        v-show="!!defaultEncryption && backupToken"
        :label="i18n.encrypted"
        v-model="isEncrypted"
      >
        <option value="true">{{ i18n.yes }}</option>
        <option value="false">{{ i18n.no }}</option>
      </a-select-input>
      <a-button v-show="backupToken" @click="backupLogout()">
        {{ i18n.log_out }}
      </a-button>
      <a-button v-show="!backupToken" @click="saveCredentials()">
        {{ i18n.save }}
      </a-button>
      <a-button v-show="backupToken" @click="backupUpload()">
        {{ i18n.manual_webdav }}
      </a-button>
    </div>
  </div>
</template>
<script lang="ts">
import Vue from "vue";
import { WebDAV } from "../../models/backup";
import { UserSettings } from "../../models/settings";

const service = "webdav";

export default Vue.extend({
  data: function () {
    return {
      username: this.i18n.loading,
      webdavUrl: "",
      webdavUsername: "",
      webdavPassword: "",
    };
  },
  created() {
    UserSettings.updateItems();
    this.webdavUrl = UserSettings.items.webdavUrl || "";
    this.webdavUsername = UserSettings.items.webdavUsername || "";
    this.webdavPassword = UserSettings.items.webdavPassword || "";
  },
  computed: {
    defaultEncryption: function () {
      return this.$store.state.accounts.defaultEncryption;
    },
    isEncrypted: {
      get(): boolean {
        if (UserSettings.items[`${service}Encrypted`] === null) {
          this.$store.commit("backup/setEnc", { service, value: true });
          UserSettings.items[`${service}Encrypted`] = true;
          UserSettings.commitItems();
          return true;
        }
        return this.$store.state.backup.webdavEncrypted;
      },
      set(newValue: string) {
        UserSettings.items.webdavEncrypted = newValue === "true";
        UserSettings.commitItems();
        this.$store.commit("backup/setEnc", { service, value: newValue });
      },
    },
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
      UserSettings.items.webdavUrl = this.webdavUrl;
      UserSettings.items.webdavUsername = this.webdavUsername;
      UserSettings.items.webdavPassword = this.webdavPassword;
      UserSettings.commitItems();
      
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
      this.$store.commit("backup/setToken", { service, value: false });
      this.$store.commit("style/hideInfo");
      this.webdavUrl = "";
      this.webdavUsername = "";
      this.webdavPassword = "";
    },
    async backupUpload() {
      const webdav = new WebDAV();
      const response = await webdav.upload(this.$store.state.accounts.encryption);
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
