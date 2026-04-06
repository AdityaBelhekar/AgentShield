import { spawn, ChildProcess } from 'child_process';
import * as net from 'net';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';

export class BackendManager {
    private static process: ChildProcess | null = null;
    private static port: number = 8765;
    private static logs: string[] = [];
    private static maxLogs: number = 500;

    static getPort(): number {
        return this.port;
    }

    static getLogs(): string[] {
        return this.logs;
    }

    private static addLog(log: string) {
        const text = log.toString().trim();
        if (!text) return;
        this.logs.push(...text.split('\n'));
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(this.logs.length - this.maxLogs);
        }
    }

    private static async findAvailablePort(startPort: number): Promise<number> {
        return new Promise((resolve) => {
            const server = net.createServer();
            server.listen(startPort, () => {
                const { port } = server.address() as net.AddressInfo;
                server.close(() => resolve(port));
            });
            server.on('error', () => {
                resolve(this.findAvailablePort(startPort + 1));
            });
        });
    }

    private static getPythonPath(): string {
        const isWin = os.platform() === 'win32';
        const venvPythonPath = path.join(process.resourcesPath, 'venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python');
        
        if (fs.existsSync(venvPythonPath)) {
            return venvPythonPath;
        }

        const devVenvPath = path.join(__dirname, '..', '..', '..', '.venv', isWin ? 'Scripts' : 'bin', isWin ? 'python.exe' : 'python');
        if (fs.existsSync(devVenvPath)) {
            return devVenvPath;
        }

        return isWin ? 'python' : 'python3';
    }

    static async start(): Promise<void> {
        this.port = await this.findAvailablePort(8765);
        const pythonPath = this.getPythonPath();
        
        let backendDir = path.join(__dirname, '..', '..', '..');
        if (process.env.NODE_ENV === 'production' || __dirname.includes('app.asar')) {
            backendDir = process.resourcesPath;
        }

        this.addLog(`Starting backend on port ${this.port} using ${pythonPath}`);

        this.process = spawn(pythonPath, ['-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', this.port.toString()], {
            cwd: backendDir,
            env: { ...process.env, PYTHONPATH: backendDir }
        });

        if (this.process.stdout) {
            this.process.stdout.on('data', (data) => this.addLog(data.toString()));
        }
        if (this.process.stderr) {
            this.process.stderr.on('data', (data) => this.addLog(data.toString()));
        }

        this.process.on('close', (code) => {
            this.addLog(`Backend process exited with code ${code}`);
            this.process = null;
        });
    }

    static stop(): void {
        if (this.process) {
            if (os.platform() === 'win32') {
                spawn('taskkill', ['/pid', this.process.pid?.toString() || '', '/t', '/f']);
            } else {
                try {
                    process.kill(-this.process.pid!);
                } catch (e) {
                    this.process.kill();
                }
            }
            this.process = null;
        }
    }
}
