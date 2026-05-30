const runtime = document.querySelector("#runtime");
const platform = document.querySelector("#platform");

runtime.textContent = `Electron ${window.electronCli.versions.electron}`;
platform.textContent = window.electronCli.platform;
