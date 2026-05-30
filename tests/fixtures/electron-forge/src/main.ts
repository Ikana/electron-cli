import { app, BrowserWindow } from "electron";

function createWindow() {
  const window = new BrowserWindow({ width: 800, height: 600 });
  window.loadURL("about:blank");
}

app.whenReady().then(createWindow);
