const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { spawn, execSync } = require('child_process');
const fs = require('fs');

let mainWindow;
let pythonProcess;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 800,
        icon: path.join(__dirname, 'build', 'icon.png'),
        titleBarStyle: 'hidden',
        backgroundColor: '#0f172a', // Slate 900
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
        },
    });

    // In development, we might use a dev server. 
    // For now, load a static HTML file.
    mainWindow.loadFile('src/index.html');

    // Open DevTools in debug mode
    // mainWindow.webContents.openDevTools();
}

// Start the Python Sidecar (gui_bridge.py / compiled binary)
function startPythonSidecar() {
    console.log('[*] Starting WSHawk Python Sidecar...');

    let executablePath;
    let args = [];
    let options = {};

    const bridgePort = process.env.WSHAWK_BRIDGE_PORT || '8080';

    if (app.isPackaged) {
        // Run the compiled self-contained binary natively
        if (process.platform === 'win32') {
            executablePath = path.join(process.resourcesPath, 'bin', 'wshawk-bridge.exe');
        } else {
            // Check standard resources path (for AppImage/Bundled)
            const bundledPath = path.join(process.resourcesPath, 'bin', 'wshawk-bridge');
            // Check system-wide path (for Arch/AUR/Debian installs where we use system electron)
            const systemPath = path.join(__dirname, 'bin', 'wshawk-bridge');

            if (fs.existsSync(systemPath)) {
                executablePath = systemPath;
            } else {
                executablePath = bundledPath;
            }
        }

        // Check if binary exists
        if (!fs.existsSync(executablePath)) {
            console.error(`[FATAL] Sidecar binary not found at: ${executablePath}`);
            dialog.showErrorBox(
                'WSHawk Sidecar Missing',
                `Could not find the Python sidecar binary at:\n${executablePath}\n\nPlease reinstall WSHawk.`
            );
            return;
        }

        // Fix execute permissions on macOS/Linux (DMG strips them)
        if (process.platform !== 'win32') {
            try {
                // Only attempt chmod if we have write access (fails on system-wide root installs)
                fs.accessSync(executablePath, fs.constants.W_OK);
                fs.chmodSync(executablePath, 0o755);
                console.log(`[+] Set execute permission on sidecar binary`);
            } catch (e) {
                // If it's a system install, it's already +x from the package manager
                if (e.code !== 'EACCES' && e.code !== 'EPERM') {
                    console.error(`[-] Failed to set execute permission: ${e.message}`);
                }
            }
        }

        options = { stdio: 'pipe', env: { ...process.env, WSHAWK_BRIDGE_PORT: bridgePort } };
    } else {
        // Development mode: Run the script using system python3 as a module
        executablePath = process.platform === 'win32' ? 'python' : 'python3';
        options = {
            cwd: path.join(__dirname, '..'),
            stdio: 'pipe',
            env: { ...process.env, WSHAWK_BRIDGE_PORT: bridgePort }
        };
        args = ['-m', 'wshawk.gui_bridge'];
    }

    console.log(`[Main] Spawning: ${executablePath} ${args.join(' ')} (CWD: ${options.cwd || 'default'})`);
    console.log(`[Main] Platform: ${process.platform}, Arch: ${process.arch}, Packaged: ${app.isPackaged}`);

    try {
        pythonProcess = spawn(executablePath, args, options);
    } catch (e) {
        console.error(`[FATAL] Failed to spawn sidecar: ${e.message}`);
        dialog.showErrorBox('WSHawk Sidecar Error', `Failed to start Python engine:\n${e.message}`);
        return;
    }

    pythonProcess.stdout.on('data', (data) => {
        const text = data.toString();
        console.log(`[Python] ${text}`);

        // Parse the actual port the bridge chose (may differ from 8080 if taken)
        const portMatch = text.match(/\[BRIDGE_PORT\]\s*(\d+)/);
        if (portMatch) {
            const actualPort = parseInt(portMatch[1], 10);
            console.log(`[Main] Bridge is listening on port ${actualPort}`);
            if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
                mainWindow.webContents.send('bridge-port', actualPort);
            }
        }
    });

    pythonProcess.stderr.on('data', (data) => {
        const msg = data.toString();
        console.error(`[Python Error] ${msg}`);
        // Send to renderer so user sees it in system log
        if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
            mainWindow.webContents.send('sidecar-error', msg);
        }
    });

    pythonProcess.on('exit', (code, signal) => {
        console.error(`[Main] Sidecar exited with code=${code}, signal=${signal}`);
        if (code !== 0 && code !== null) {
            if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
                mainWindow.webContents.send('sidecar-error', `Sidecar crashed (exit code ${code})`);
            }
        }
    });

    pythonProcess.on('error', (err) => {
        console.error(`[FATAL] Sidecar process error: ${err.message}`);
        dialog.showErrorBox('WSHawk Sidecar Error', `Python engine failed to start:\n${err.message}`);
    });
}

function checkPythonDependency() {
    try {
        let pyVersion = "";
        try {
            pyVersion = execSync('python3 --version', { encoding: 'utf8', stdio: 'pipe' });
        } catch (e) {
            pyVersion = execSync('python --version', { encoding: 'utf8', stdio: 'pipe' });
        }
        console.log(`[+] System Python Check Passed: ${pyVersion.trim()}`);
    } catch (err) {
        console.error("[-] Python not found on the system");
        const resp = dialog.showMessageBoxSync({
            type: 'error',
            title: 'Critical Dependency Missing',
            message: 'WSHawk requires Python 3.8+ to execute automated exploit payloads and verification sequences.\n\nPlease install Python and restart the application.',
            buttons: ['Download Python', 'Quit WSHawk']
        });

        if (resp === 0) {
            shell.openExternal('https://www.python.org/downloads/');
        }
        app.quit();
    }
}

app.whenReady().then(() => {
    // Only check for system Python in dev mode — packaged builds use
    // the self-contained wshawk-bridge binary (PyInstaller) which bundles
    // its own Python interpreter and all pip dependencies.
    if (!app.isPackaged) checkPythonDependency();
    startPythonSidecar();
    createWindow();

    // Setup native dialog handlers for Project Management
    ipcMain.handle('dialog:openProject', async () => {
        const result = await dialog.showOpenDialog(mainWindow, {
            title: 'Open WSHawk Project',
            filters: [{ name: 'WSHawk Projects', extensions: ['wshawk'] }],
            properties: ['openFile']
        });

        if (!result.canceled && result.filePaths.length > 0) {
            try {
                const data = fs.readFileSync(result.filePaths[0], 'utf-8');
                return { success: true, data: JSON.parse(data), path: result.filePaths[0] };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:saveProject', async (event, projectData) => {
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Save WSHawk Project',
            filters: [{ name: 'WSHawk Projects', extensions: ['wshawk'] }],
            defaultPath: `project_wshawk_${Date.now()}.wshawk`
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, JSON.stringify(projectData, null, 2), 'utf-8');
                return { success: true, path: result.filePath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:exportReport', async (event, htmlContent) => {
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Export HTML Report',
            filters: [{ name: 'HTML Document', extensions: ['html'] }],
            defaultPath: `WSHawk_Report_${Date.now()}.html`
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, htmlContent, 'utf-8');
                return { success: true, path: result.filePath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:exportExploit', async (event, explData) => {
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Export Exploit PoC',
            filters: [{ name: 'Python Script', extensions: ['py'] }],
            defaultPath: `exploit_${Date.now()}.py`
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, explData, 'utf-8');
                return { success: true, path: result.filePath };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.on('window:minimize', () => {
        if (mainWindow) mainWindow.minimize();
    });

    ipcMain.on('window:maximize', () => {
        if (mainWindow) {
            if (mainWindow.isMaximized()) {
                mainWindow.restore();
            } else {
                mainWindow.maximize();
            }
        }
    });

    ipcMain.on('window:close', () => {
        if (mainWindow) mainWindow.close();
    });

    app.on('activate', function () {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', function () {
    // Kill Python sidecar when Electron exits
    if (pythonProcess) {
        pythonProcess.kill();
    }
    if (process.platform !== 'darwin') app.quit();
});
