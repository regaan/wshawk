#!/usr/bin/env python3
"""
WSHawk Advanced CLI - Easy command-line interface for all v4.0.0 features
"""

import asyncio
import argparse
import os
from .__main__ import Logger, Colors


async def main():
    """Advanced CLI with options"""
    parser = argparse.ArgumentParser(
        description='WSHawk v4.0.0 - Advanced WebSocket Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  wshawk-advanced ws://target.com                    # Quick scan
  wshawk-advanced ws://target.com --playwright       # With browser XSS verification
  wshawk-advanced ws://target.com --no-oast          # Disable OAST
  wshawk-advanced ws://target.com --rate 5           # 5 requests/second
  wshawk-advanced ws://target.com --full             # All features enabled
  wshawk-advanced https://target.com --discover      # Discover WS endpoints first
  wshawk-advanced ws://target.com --format json      # Export as JSON
  wshawk-advanced ws://target.com --format all       # Export all formats
  wshawk-advanced ws://target.com --binary           # Binary message analysis
  wshawk-advanced ws://target.com --smart-payloads   # Adaptive payload generation
  wshawk-advanced ws://target.com --defectdojo URL   # Push to DefectDojo
  wshawk-advanced ws://target.com --jira URL         # Create Jira tickets
  wshawk-advanced ws://target.com --webhook URL      # Notify via webhook
  wshawk-advanced --web                              # Launch Web GUI
  wshawk-advanced --web --port 8080                  # Web GUI on custom port
        '''
    )
    
    parser.add_argument('url', nargs='?', default=None, 
                       help='Target URL (ws://, wss://, http://, or https://)')
    parser.add_argument('--playwright', action='store_true', 
                       help='Enable Playwright browser for XSS verification')
    parser.add_argument('--no-oast', action='store_true',
                       help='Disable OAST (Out-of-Band) testing')
    parser.add_argument('--rate', type=int, default=10,
                       help='Max requests per second (default: 10)')
    parser.add_argument('--full', action='store_true',
                       help='Enable ALL features (Playwright + OAST + Session tests)')
    parser.add_argument('--discover', action='store_true',
                       help='Discover WebSocket endpoints from HTTP target before scanning')
    parser.add_argument('--format', choices=['json', 'csv', 'sarif', 'all'], default=None,
                       help='Additional report format. Use "all" for JSON+CSV+SARIF')
    parser.add_argument('--output', '-o', type=str, default=None,
                       help='Output file path for report')
    parser.add_argument('--binary', action='store_true',
                       help='Enable binary WebSocket message analysis')
    
    # ─── Integration flags ──────────────────────────────────────
    integ = parser.add_argument_group('Integrations')
    integ.add_argument('--defectdojo', type=str, default=None, metavar='URL',
                       help='Push results to DefectDojo (requires DEFECTDOJO_API_KEY env var)')
    integ.add_argument('--dd-product', type=int, default=None,
                       help='DefectDojo product ID')
    integ.add_argument('--jira', type=str, default=None, metavar='URL',
                       help='Create Jira tickets (requires JIRA_EMAIL and JIRA_API_TOKEN env vars)')
    integ.add_argument('--jira-project', type=str, default='SEC',
                       help='Jira project key (default: SEC)')
    integ.add_argument('--webhook', type=str, default=None, metavar='URL',
                       help='Send results to webhook (auto-detects Slack/Discord/Teams)')
    integ.add_argument('--webhook-platform', choices=['slack', 'discord', 'teams', 'generic'],
                       default='generic', help='Webhook platform (default: auto-detect)')
    
    # ─── Smart Payloads ─────────────────────────────────────────
    smart = parser.add_argument_group('Smart Payloads')
    smart.add_argument('--smart-payloads', action='store_true',
                       help='Enable context-aware adaptive payload generation')
    
    # ─── Web GUI ────────────────────────────────────────────────
    web = parser.add_argument_group('Web GUI')
    web.add_argument('--web', action='store_true',
                     help='Launch Flask-based Web GUI instead of CLI scan')
    web.add_argument('--host', type=str, default='0.0.0.0',
                     help='Web GUI host (default: 0.0.0.0)')
    web.add_argument('--port', type=int, default=5000,
                     help='Web GUI port (default: 5000)')
    args = parser.parse_args()
    
    # Load configuration
    from .config import WSHawkConfig
    config = WSHawkConfig.load()
    
    # Override config with CLI flags
    if args.host: config.set('web.host', args.host)
    if args.port: config.set('web.port', args.port)
    if args.rate: config.set('scanner.rate_limit', args.rate)
    if args.playwright: config.set('scanner.features.playwright', True)
    if args.no_oast: config.set('scanner.features.oast', False)
    if args.binary: config.set('scanner.features.binary_analysis', True)
    if args.smart_payloads: config.set('scanner.features.smart_payloads', True)

    # ─── Web GUI Mode ──────────────────────────────────────────
    if args.web:
        from .web.app import run_web
        Logger.banner()
        Logger.info("Launching WSHawk Web GUI...")
        
        # Get settings from config
        host = config.get('web.host')
        port = config.get('web.port')
        auth_enabled = config.get('web.auth.enabled')
        auth_password = config.get('web.auth.password')
        db_path = config.get('web.database') # This will be passed as None to Use default in ScanDatabase
        
        # db_path in config might be 'sqlite:///wshawk.db', we need just path
        clean_db_path = None
        if db_path and db_path.startswith('sqlite:///'):
            clean_db_path = db_path.replace('sqlite:///', '')
            
        run_web(
            host=host, 
            port=port, 
            auth_enabled=auth_enabled, 
            auth_password=auth_password,
            db_path=clean_db_path
        )
        return
    
    # URL is required for scan modes
    if not args.url:
        parser.error("the following arguments are required: url (or use --web for Web GUI)")

    Logger.banner()
    
    # ─── Discovery Mode ─────────────────────────────────────────
    if args.discover or args.url.startswith(('http://', 'https://')):
        Logger.info("Running WebSocket Endpoint Discovery...")
        print()
        
        from .ws_discovery import WSEndpointDiscovery
        
        discovery = WSEndpointDiscovery(args.url)
        endpoints = await discovery.discover()
        
        if not endpoints:
            Logger.error("No WebSocket endpoints discovered. Provide a ws:// or wss:// URL directly.")
            return
        
        # Use the highest-confidence endpoint
        best = endpoints[0]
        scan_url = best['url']
        Logger.success(f"Using discovered endpoint: {scan_url} [{best['confidence']}]")
        print()
        
        # If there are multiple, show them all
        if len(endpoints) > 1:
            Logger.info(f"Other endpoints found ({len(endpoints)-1} more):")
            for ep in endpoints[1:]:
                print(f"  - {ep['url']} [{ep['confidence']}]")
            print()
    else:
        scan_url = args.url
    
    # Validate URL
    if not scan_url.startswith(('ws://', 'wss://')):
        Logger.error("URL must start with ws:// or wss:// (or use --discover with an HTTP URL)")
        return
    
    Logger.info("WSHawk v4.0.0 - Advanced Scanner")
    Logger.info(f"Target: {scan_url}")
    Logger.info(f"Rate limit: {config.get('scanner.rate_limit')} req/s")
    
    # Create scanner with config
    scanner = WSHawkV2(scan_url, config=config)
    
    # Configure features from config/args
    if args.full:
        scanner.use_headless_browser = True
        scanner.use_oast = True
        scanner.use_smart_payloads = True
        Logger.info("Mode: FULL (All features enabled)")
    else:
        scanner.use_headless_browser = config.get('scanner.features.playwright')
        scanner.use_oast = config.get('scanner.features.oast')
        scanner.use_smart_payloads = config.get('scanner.features.smart_payloads')
        
        features = []
        if scanner.use_headless_browser:
            features.append("Playwright XSS")
        if scanner.use_oast:
            features.append("OAST")
        if args.binary:
            features.append("Binary Analysis")
        if scanner.use_smart_payloads:
            features.append("Smart Payloads")
        
        Logger.info(f"Features: {', '.join(features) if features else 'Standard'}")
    
    # Configure integrations
    integrations = []
    if args.defectdojo:
        integrations.append('DefectDojo')
    if args.jira:
        integrations.append('Jira')
    if args.webhook:
        integrations.append(f'Webhook ({args.webhook_platform})')
    if integrations:
        Logger.info(f"Integrations: {', '.join(integrations)}")
    
    print()
    
    # Run scan
    vulns = await scanner.run_heuristic_scan()
    
    # ─── Additional Report Exports ──────────────────────────────
    scan_info = {
        'target': scan_url,
        'duration': (scanner.end_time - scanner.start_time).total_seconds() if scanner.start_time and scanner.end_time else 0,
        'messages_sent': scanner.messages_sent,
        'messages_received': scanner.messages_received,
    }
    
    if args.format and vulns is not None:
        from .report_exporter import ReportExporter
        exporter = ReportExporter()
        
        formats = ['json', 'csv', 'sarif'] if args.format == 'all' else [args.format]
        
        for fmt in formats:
            output_file = args.output if args.output and len(formats) == 1 else None
            path = exporter.export(scanner.vulnerabilities, scan_info, fmt, output_file)
            Logger.success(f"{fmt.upper()} report saved: {path}")
    
    # ─── Integrations ──────────────────────────────────────────
    vuln_list = vulns or []
    
    if args.defectdojo and vuln_list:
        api_key = os.environ.get('DEFECTDOJO_API_KEY', '')
        if not api_key:
            Logger.error("Set DEFECTDOJO_API_KEY environment variable")
        else:
            from .integrations.defectdojo import DefectDojoIntegration
            dd = DefectDojoIntegration(
                url=args.defectdojo,
                api_key=api_key,
                product_id=args.dd_product,
            )
            result = await dd.push_results(vuln_list, scan_info)
            if result.get('success'):
                Logger.success(f"DefectDojo: {result.get('findings_imported', 0)} findings imported")
            else:
                Logger.error(f"DefectDojo: {result.get('error', 'Unknown error')}")
    
    if args.jira and vuln_list:
        email = os.environ.get('JIRA_EMAIL', '')
        token = os.environ.get('JIRA_API_TOKEN', '')
        if not email or not token:
            Logger.error("Set JIRA_EMAIL and JIRA_API_TOKEN environment variables")
        else:
            from .integrations.jira_connector import JiraIntegration
            jira = JiraIntegration(
                url=args.jira,
                email=email,
                api_token=token,
                project_key=args.jira_project,
            )
            tickets = await jira.create_tickets(vuln_list, scan_info)
            Logger.success(f"Jira: {len(tickets)} tickets created")
    
    if args.webhook:
        from .integrations.webhook import WebhookNotifier
        
        # Auto-detect platform from URL
        platform = args.webhook_platform
        if platform == 'generic':
            if 'slack.com' in args.webhook or 'hooks.slack' in args.webhook:
                platform = 'slack'
            elif 'discord.com' in args.webhook or 'discordapp.com' in args.webhook:
                platform = 'discord'
            elif 'office.com' in args.webhook or 'webhook.office' in args.webhook:
                platform = 'teams'
        
        notifier = WebhookNotifier(webhook_url=args.webhook, platform=platform)
        await notifier.notify(vuln_list, scan_info)
    
    Logger.success("Scan complete!")


def cli():
    """Entry point"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    cli()
