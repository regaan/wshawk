'use strict';

const { spawn } = require('child_process');
const crypto = require('crypto');
const readline = require('readline');
const { EventEmitter } = require('events');

const {
    IPC_VERSION,
    MAX_RESPONSE_BYTES,
    WORKER_METHODS,
    jsonByteLength,
} = require('../shared/contract');

class WorkerClient extends EventEmitter {
    constructor(options) {
        super();
        this.executable = options.executable;
        this.args = options.args || [];
        this.cwd = options.cwd;
		this.environment = options.environment || {};
        this.requestTimeoutMs = options.requestTimeoutMs || 10_000;
        this.child = null;
        this.pending = new Map();
        this.stopping = false;
        this.stderr = [];
    }

    async start() {
        if (this.child) return;

        await new Promise((resolve, reject) => {
            const child = spawn(this.executable, this.args, {
                cwd: this.cwd,
                env: { ...process.env, ...this.environment, WSHAWK_WORKER_TRANSPORT: 'stdio' },
                shell: false,
                stdio: ['pipe', 'pipe', 'pipe'],
                windowsHide: true,
            });
            this.child = child;

            const lines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
            lines.on('line', (line) => this.#handleLine(line));
            child.stderr.setEncoding('utf8');
            child.stderr.on('data', (chunk) => this.#rememberDiagnostic(chunk));

            child.once('spawn', () => {
                this.emit('status', { state: 'running', pid: child.pid });
                resolve();
            });
            child.once('error', (error) => {
                if (this.child === child) this.child = null;
                reject(error);
            });
            child.once('exit', (code, signal) => {
                if (this.child === child) this.child = null;
                const expected = this.stopping;
                this.stopping = false;
                this.#rejectPending(new Error(`Go worker exited (${code ?? signal ?? 'unknown'})`));
                this.emit('status', { state: expected ? 'stopped' : 'crashed', code, signal });
            });
        });
    }

    async request(method, params = {}, timeoutMs = this.requestTimeoutMs) {
        if (!WORKER_METHODS.includes(method)) {
            throw new TypeError(`Unsupported Go worker method: ${method}`);
        }
        if (!this.child?.stdin?.writable) {
            throw new Error('Go worker is not running');
        }

        const id = crypto.randomUUID();
        const request = { version: IPC_VERSION, id, method, params };
        const encoded = `${JSON.stringify(request)}\n`;

        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pending.delete(id);
                reject(new Error(`Go worker request timed out: ${method}`));
            }, timeoutMs);
            timer.unref?.();
            this.pending.set(id, { resolve, reject, timer, method });
            this.child.stdin.write(encoded, 'utf8', (error) => {
                if (!error) return;
                const pending = this.pending.get(id);
                if (!pending) return;
                clearTimeout(pending.timer);
                this.pending.delete(id);
                reject(error);
            });
        });
    }

    async stop() {
        const child = this.child;
        if (!child) return;
        this.stopping = true;
        try {
            await this.request('system.shutdown', {}, 2_000);
        } catch (error) {
            this.#rememberDiagnostic(`Graceful worker shutdown failed: ${error.message}`);
        }
        if (this.child === child) {
            child.stdin.end();
            const killTimer = setTimeout(() => child.kill(), 2_000);
            killTimer.unref?.();
        }
    }

    #handleLine(line) {
        if (!line.trim()) return;
        if (Buffer.byteLength(line, 'utf8') > MAX_RESPONSE_BYTES) {
            this.#rejectPending(new RangeError('Go worker response exceeded the payload limit'));
            this.child?.kill();
            return;
        }

        let message;
        try {
            message = JSON.parse(line);
        } catch (error) {
            this.#rememberDiagnostic(`Rejected invalid worker JSON: ${error.message}`);
            return;
        }

        if (message.event) {
            this.emit('event', message);
            return;
        }
        const pending = this.pending.get(message.id);
        if (!pending) return;
        clearTimeout(pending.timer);
        this.pending.delete(message.id);

        if (message.version !== IPC_VERSION) {
            pending.reject(new Error('Go worker protocol version mismatch'));
        } else if (message.error) {
            const error = new Error(message.error.message || 'Go worker request failed');
            error.code = message.error.code;
            error.detail = message.error.detail;
            pending.reject(error);
        } else if (jsonByteLength(message.result) > MAX_RESPONSE_BYTES) {
            pending.reject(new RangeError('Go worker result exceeded the payload limit'));
        } else {
            pending.resolve(message.result);
        }
    }

    #rememberDiagnostic(value) {
        const line = String(value || '').trim().slice(0, 2_048);
        if (!line) return;
        this.stderr.push(line);
        if (this.stderr.length > 40) this.stderr.shift();
        this.emit('diagnostic', line);
    }

    #rejectPending(error) {
        for (const pending of this.pending.values()) {
            clearTimeout(pending.timer);
            pending.reject(error);
        }
        this.pending.clear();
    }
}

module.exports = { WorkerClient };
