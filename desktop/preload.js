const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('api', {
    send: (channel, data) => {
        // Whitelist channels
        let validChannels = ['toMain', 'window:minimize', 'window:maximize', 'window:close'];
        if (validChannels.includes(channel)) {
            ipcRenderer.send(channel, data);
        }
    },
    receive: (channel, func) => {
        let validChannels = [
            'fromMain',
            'scan_update',
            'vulnerability_found',
            'scan_progress',
            'intercepted_frame',
            'bridge-port',
            'bridge-ready',
            'sidecar-error',
        ];
        if (validChannels.includes(channel)) {
            // Deliberately strip event as it includes `sender` 
            ipcRenderer.on(channel, (event, ...args) => func(...args));
        }
    },
    invoke: (channel, data) => {
        let validChannels = ['dialog:openProject', 'dialog:saveProject', 'dialog:exportReport', 'dialog:exportExploit'];
        if (validChannels.includes(channel)) {
            return ipcRenderer.invoke(channel, data);
        }
    }
});
