import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('agentshield', {
    getBackendPort: () => ipcRenderer.invoke('get-backend-port'),
    getBackendLogs: () => ipcRenderer.invoke('get-backend-logs'),
    minimizeWindow: () => ipcRenderer.send('window-minimize'),
    maximizeWindow: () => ipcRenderer.send('window-maximize'),
    closeWindow:    () => ipcRenderer.send('window-close'),
    onBackendStatus: (cb: (event: any, status: boolean) => void) => {
        ipcRenderer.on('backend-status', cb);
        return () => {
            // Need this to correctly remove listeners in React so it doesn't duplicate
            ipcRenderer.removeAllListeners('backend-status');
        };
    },
    platform: process.platform,
});
