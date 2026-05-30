const { contextBridge } = require("electron");

contextBridge.exposeInMainWorld("electronCli", {
  platform: process.platform,
  versions: process.versions,
});
