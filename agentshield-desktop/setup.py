import os
import json

app_dir = '.'
os.makedirs('electron', exist_ok=True)
os.makedirs('resources', exist_ok=True)
os.makedirs('src', exist_ok=True)

with open('package.json', 'r') as f:
    pkg = json.load(f)

pkg['main'] = 'dist/electron/main.js'
pkg['scripts']['dev'] = 'concurrently "vite" "wait-on http://localhost:5173 && electron ."'
pkg['scripts']['build'] = 'vite build && electron-builder'
pkg['scripts']['build:win'] = 'electron-builder --win'
pkg['scripts']['build:mac'] = 'electron-builder --mac'
pkg['scripts']['build:linux'] = 'electron-builder --linux'

with open('package.json', 'w') as f:
    json.dump(pkg, f, indent=2)

with open('electron/main.ts', 'w') as f:
    f.write('''import { app, BrowserWindow, ipcMain } from "electron";
import * as path from "path";
import { BackendManager } from "./backend-manager";

let mainWindow: BrowserWindow | null = null;
app.on("ready", async () => {
    try {
        await BackendManager.start();
        mainWindow = new BrowserWindow({
            width: 1280, height: 800, minWidth: 960, minHeight: 600,
            titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "hidden",
            backgroundColor: "#0E0E0E",
            show: false,
            webPreferences: {
                preload: path.join(__dirname, "preload.js"),
                contextIsolation: true,
                nodeIntegration: false
            }
        });
        
        // Load index.html or URL based on DEV vs PROD...
        mainWindow.loadURL("http://localhost:5173");
        mainWindow.on("ready-to-show", () => mainWindow?.show());
    } catch (e) {
        console.error(e);
        app.quit();
    }
});
app.on("window-all-closed", () => {
    BackendManager.stop();
    app.quit();
});
    ''')

with open('electron/backend-manager.ts', 'w') as f:
    f.write('''export class BackendManager {
    static async start() { /* ... */ }
    static stop() { /* ... */ }
    static getLogs() { return []; }
    static getPort() { return 8765; }
}''')

with open('electron/preload.ts', 'w') as f:
    f.write('''import { contextBridge, ipcRenderer } from "electron";
contextBridge.exposeInMainWorld("agentshield", {
    getBackendPort: () => 8765,
    getBackendLogs: () => [],
    platform: process.platform
});''')

with open('electron-builder.config.js', 'w') as f:
    f.write('''module.exports = { appId: "dev.agentshield.desktop" };''')
