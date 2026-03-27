#!/usr/bin/env python3
"""
WSHawk Web GUI - Flask-based Dashboard & REST API
SQLite persistence, auth, resilient background scanning

Author: Regaan (@regaan)
"""

import asyncio
import json
import os
import sqlite3
import hashlib
import secrets
import threading
import uuid
from datetime import datetime
from functools import wraps
from typing import Dict, List, Optional

try:
    from flask import (
        Flask, render_template, request, jsonify,
        send_file, redirect, url_for, session, g, abort
    )
except ImportError:
    Flask = None

try:
    from ..__main__ import Logger
except ImportError:
    class Logger:
        @staticmethod
        def info(msg): print(f"[*] {msg}")
        @staticmethod
        def success(msg): print(f"[+] {msg}")
        @staticmethod
        def error(msg): print(f"[-] {msg}")


try:
    from ..db_manager import WSHawkDatabase
except ImportError:
    # Fallback if relative import fails during development
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from db_manager import WSHawkDatabase


# ─── SQLite Persistence Layer ───────────────────────────────────
# Internal ScanDatabase removed in favor of unified WSHawkDatabase


# ─── Authentication ─────────────────────────────────────────────

def hash_password(password: str, salt: str = None) -> tuple:
    """Hash password with salt using SHA-256."""
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return hashed, salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verify a password against hash."""
    check, _ = hash_password(password, salt)
    return secrets.compare_digest(check, hashed)


def require_auth(f):
    """Decorator to require authentication (when auth is enabled)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        app = args[0] if args else None
        
        # Check if auth is enabled via app config
        from flask import current_app
        if not current_app.config.get('AUTH_ENABLED', False):
            return f(*args, **kwargs)
        
        # Check session
        if session.get('authenticated'):
            return f(*args, **kwargs)
        
        # Check API key header
        api_key = request.headers.get('X-API-Key')
        if api_key and api_key == current_app.config.get('API_KEY'):
            return f(*args, **kwargs)
        
        # Redirect to login for web, 401 for API
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Authentication required'}), 401
        
        return redirect(url_for('login'))
    
    return decorated


# ─── Background Scan Runner ────────────────────────────────────

def run_scan_background(store: WSHawkDatabase, scan_id: str):
    """Run a scan in a background thread with proper error handling."""
    scan = store.get(scan_id)
    if not scan:
        return
    
    store.update(scan_id, status='running', started_at=datetime.now().isoformat())
    
    try:
        from ..scanner_v2 import WSHawkV2
        
        target = scan['target']
        options = scan['options']
        
        scanner = WSHawkV2(
            target,
            max_rps=options.get('rate', 10)
        )
        scanner.use_headless_browser = options.get('playwright', False)
        scanner.use_oast = options.get('oast', True)
        
        # Run scan in async context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            vulns = loop.run_until_complete(scanner.run_heuristic_scan())
            
            duration = 0
            if scanner.start_time and scanner.end_time:
                duration = (scanner.end_time - scanner.start_time).total_seconds()
            
            store.update(
                scan_id,
                status='completed',
                completed_at=datetime.now().isoformat(),
                findings_json=vulns or [],
                messages_sent=scanner.messages_sent,
                messages_received=scanner.messages_received,
                duration=duration,
                progress=100,
            )
        finally:
            loop.close()
        
    except Exception as e:
        store.update(
            scan_id,
            status='failed',
            error=str(e),
            completed_at=datetime.now().isoformat(),
        )


# ─── Flask App Factory ─────────────────────────────────────────

def create_app(
    db_path: str = None,
    auth_enabled: bool = False,
    auth_username: str = 'admin',
    auth_password: str = None,
) -> 'Flask':
    """
    Create and configure the Flask application.
    
    Args:
        db_path: Path to SQLite database file
        auth_enabled: Enable login requirement
        auth_username: Admin username
        auth_password: Admin password (required if auth_enabled)
    """
    if not Flask:
        raise ImportError("Flask required for web GUI. Install: pip install flask")
    
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    
    app = Flask(
        __name__,
        template_folder=template_dir,
        static_folder=static_dir,
    )
    app.secret_key = os.environ.get('WSHAWK_SECRET_KEY', secrets.token_hex(32))
    
    # Auth configuration
    app.config['AUTH_ENABLED'] = auth_enabled
    if auth_enabled and auth_password:
        hashed, salt = hash_password(auth_password)
        app.config['AUTH_USERNAME'] = auth_username
        app.config['AUTH_PASSWORD_HASH'] = hashed
        app.config['AUTH_PASSWORD_SALT'] = salt
    
    # Generate API key for programmatic access
    app.config['API_KEY'] = os.environ.get('WSHAWK_API_KEY', secrets.token_hex(16))
    
    # Initialize database
    store = WSHawkDatabase(db_path)
    
    # ─── Auth Routes ────────────────────────────────────────────
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if not app.config.get('AUTH_ENABLED'):
            return redirect(url_for('dashboard'))
        
        error = None
        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            
            if (username == app.config.get('AUTH_USERNAME') and
                verify_password(
                    password,
                    app.config.get('AUTH_PASSWORD_HASH', ''),
                    app.config.get('AUTH_PASSWORD_SALT', '')
                )):
                session['authenticated'] = True
                session['username'] = username
                return redirect(url_for('dashboard'))
            
            error = 'Invalid credentials'
        
        return render_template('login.html', error=error)
    
    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))
    
    # ─── Web Routes ─────────────────────────────────────────────
    
    @app.route('/')
    @require_auth
    def dashboard():
        """Main dashboard — scan history and overview."""
        scans = store.list_all()
        
        total_vulns = sum(len(s.get('findings', [])) for s in scans)
        critical_count = sum(
            1 for s in scans
            for v in s.get('findings', [])
            if v.get('confidence', v.get('severity', '')).upper() in ('CRITICAL', 'HIGH')
        )
        
        return render_template('dashboard.html',
            scans=scans,
            total_scans=len(scans),
            total_vulns=total_vulns,
            critical_count=critical_count,
        )
    
    @app.route('/scan', methods=['GET', 'POST'])
    @require_auth
    def new_scan():
        """New scan form and submission."""
        if request.method == 'POST':
            target = request.form.get('target', '').strip()
            if not target:
                return render_template('scan.html', error='Target URL is required')
            
            if not target.startswith(('ws://', 'wss://')):
                return render_template('scan.html', error='URL must start with ws:// or wss://')
            
            options = {
                'rate': int(request.form.get('rate', 10)),
                'playwright': 'playwright' in request.form,
                'oast': 'oast' in request.form,
            }
            
            scan_id = store.create(target, options)
            
            # Start scan in background
            thread = threading.Thread(
                target=run_scan_background,
                args=(store, scan_id),
                daemon=True
            )
            thread.start()
            
            return redirect(url_for('view_scan', scan_id=scan_id))
        
        return render_template('scan.html')
    
    @app.route('/scan/<scan_id>')
    @require_auth
    def view_scan(scan_id):
        """View scan results."""
        scan = store.get(scan_id)
        if not scan:
            return redirect(url_for('dashboard'))
        
        return render_template('report.html', scan=scan)
    
    @app.route('/scan/<scan_id>/delete', methods=['POST'])
    @require_auth
    def delete_scan(scan_id):
        """Delete a scan."""
        store.delete(scan_id)
        return redirect(url_for('dashboard'))
    
    # ─── REST API Routes ────────────────────────────────────────
    
    @app.route('/api/scans', methods=['GET'])
    @require_auth
    def api_list_scans():
        """List all scans."""
        limit = request.args.get('limit', 100, type=int)
        return jsonify({
            'scans': store.list_all(limit=limit),
            'total': len(store.list_all()),
        })
    
    @app.route('/api/scan', methods=['POST'])
    @require_auth
    def api_create_scan():
        """Create and start a new scan."""
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({'error': 'target is required'}), 400
        
        target = data['target']
        if not target.startswith(('ws://', 'wss://')):
            return jsonify({'error': 'URL must start with ws:// or wss://'}), 400
        
        options = {
            'rate': data.get('rate', 10),
            'playwright': data.get('playwright', False),
            'oast': data.get('oast', True),
        }
        
        scan_id = store.create(target, options)
        
        thread = threading.Thread(
            target=run_scan_background,
            args=(store, scan_id),
            daemon=True
        )
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'queued',
            'message': f'Scan started for {target}',
        }), 201
    
    @app.route('/api/scan/<scan_id>', methods=['GET'])
    @require_auth
    def api_get_scan(scan_id):
        """Get scan details."""
        scan = store.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify(scan)
    
    @app.route('/api/scan/<scan_id>/status', methods=['GET'])
    @require_auth
    def api_scan_status(scan_id):
        """Get scan status (for polling)."""
        scan = store.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify({
            'id': scan_id,
            'status': scan['status'],
            'progress': scan['progress'],
            'vulnerabilities_found': len(scan.get('findings', [])),
        })
    
    @app.route('/api/scan/<scan_id>', methods=['DELETE'])
    @require_auth
    def api_delete_scan(scan_id):
        """Delete a scan."""
        if store.delete(scan_id):
            return jsonify({'message': 'Scan deleted'})
        return jsonify({'error': 'Scan not found'}), 404
    
    @app.route('/api/scan/<scan_id>/export/<fmt>', methods=['GET'])
    @require_auth
    def api_export(scan_id, fmt):
        """Export scan results in specified format."""
        scan = store.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if fmt not in ('json', 'csv', 'sarif'):
            return jsonify({'error': 'Unsupported format. Use json, csv, or sarif'}), 400
        
        from ..report_exporter import ReportExporter
        exporter = ReportExporter()
        
        scan_info = {
            'target': scan['target'],
            'duration': scan.get('duration', 0),
            'messages_sent': scan.get('messages_sent', 0),
            'messages_received': scan.get('messages_received', 0),
        }
        
        output_path = f'/tmp/wshawk_export_{scan_id}.{fmt}'
        exporter.export(scan.get('findings', []), scan_info, fmt, output_path)
        
        return send_file(output_path, as_attachment=True)
    
    @app.route('/api/stats', methods=['GET'])
    @require_auth
    def api_stats():
        """Get aggregate scan statistics."""
        return jsonify(store.get_stats())
    
    # ─── Error Handlers ─────────────────────────────────────────
    
    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not found'}), 404
        return redirect(url_for('dashboard'))
    
    @app.errorhandler(500)
    def server_error(e):
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error'}), 500
        return render_template('dashboard.html',
            scans=[], total_scans=0, total_vulns=0, critical_count=0,
            error='An unexpected error occurred'
        )
    
    return app


# ─── CLI Entry Point ────────────────────────────────────────────

def run_web(
    host: str = '0.0.0.0',
    port: int = 5000,
    debug: bool = False,
    db_path: str = None,
    auth_enabled: bool = False,
    auth_password: str = None,
):
    """Start the WSHawk web GUI."""
    # Check for auth env var
    env_password = os.environ.get('WSHAWK_WEB_PASSWORD')
    if env_password:
        auth_enabled = True
        auth_password = env_password
    
    app = create_app(
        db_path=db_path,
        auth_enabled=auth_enabled,
        auth_password=auth_password,
    )
    
    Logger.info(f"Starting WSHawk Web GUI on http://{host}:{port}")
    if auth_enabled:
        Logger.info(f"Authentication ENABLED (user: admin)")
        Logger.info(f"API Key: {app.config['API_KEY']}")
    else:
        Logger.info("Authentication DISABLED (set WSHAWK_WEB_PASSWORD to enable)")
    Logger.info(f"Database: {WSHawkDatabase(db_path).db_path}")
    Logger.info("Press Ctrl+C to stop")
    
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    run_web(debug=True)
