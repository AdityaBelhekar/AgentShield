import { app, BrowserWindow, ipcMain, dialog } from 'electron';
import * as path from 'path';
import * as http from 'http';
import { BackendManager } from './backend-manager';

if (!app.requestSingleInstanceLock()) {
    app.quit();
}

let mainWindow: BrowserWindow | null = null;
const isDev = process.env.NODE_ENV !== 'production' && !app.isPackaged;

async function checkBackendHealth(port: number, attempt = 1, maxAttempts = 30): Promise<boolean> {
    return new Promise((resolve) => {
        const req = http.get(`http://127.0.0.1:${port}/health`, (res) => {
            if (res.statusCode === 200) {
                resolve(true);
            } else {
                resolve(false);
            }
        });
        
        req.on('error', () => {
            if (attempt >= maxAttempts) resolve(false);
            else setTimeout(() => resolve(checkBackendHealth(port, attempt + 1, maxAttempts)), 500);
        });
        
        req.setTimeout(500, () => {
            req.destroy();
            if (attempt >= maxAttempts) resolve(false);
            else setTimeout(() => resolve(checkBackendHealth(port, attempt + 1, maxAttempts)), 500);
        });
    });
}

app.on('ready', async () => {
    try {
        await BackendManager.start();
        
        const port = BackendManager.getPort();
        const isHealthy = await checkBackendHealth(port);
        
        if (!isHealthy) {
            dialog.showErrorBox(
                'AgentShield backend failed to start',
                `Could not verify backend at port ${port}. Please check the logs.`
            );
            app.quit();
            return;
        }

        mainWindow = new BrowserWindow({
            width: 1280, height: 800, minWidth: 960, minHeight: 600,
            titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'hidden',
            backgroundColor: '#0E0E0E',
            show: false,
            webPreferences: {
                preload: path.join(__dirname, 'preload.js'),
                contextIsolation: true,
                nodeIntegration: false
            }
        });

        if (isDev) {
            mainWindow.loadURL('http://localhost:5173');
        } else {
            mainWindow.loadFile(path.join(__dirname, '..', 'index.html'));
        }

        mainWindow.on('ready-to-show', () => mainWindow?.show());
        
        ipcMain.handle('get-backend-port', () => BackendManager.getPort());
        ipcMain.handle('get-backend-logs', () => BackendManager.getLogs());
        ipcMain.on('window-minimize', () => mainWindow?.minimize());
        ipcMain.on('window-maximize', () => {
            if (mainWindow?.isMaximized()) mainWindow?.unmaximize();
            else mainWindow?.maximize();
        });
        ipcMain.on('window-close', () => mainWindow?.close());

    } catch (e) {
        console.error(e);
        app.quit();
    }
});

app.on('window-all-closed', () => {
    BackendManager.stop();
    app.quit();
});

app.on('before-quit', () => {
    BackendManager.stop();
});
