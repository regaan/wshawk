#!/usr/bin/env python3
"""
WSHawk Interactive Menu
"""

import asyncio
import argparse
from ._version_info import __version__
from .console import Colors, Logger

def show_banner():
    Logger.banner()
    
def show_menu():
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Select Tests to Run:{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")
    
    print(f"{Colors.GREEN}1.{Colors.END}  SQL Injection")
    print(f"{Colors.GREEN}2.{Colors.END}  XSS - Cross-Site Scripting")
    print(f"{Colors.GREEN}3.{Colors.END}  Command Injection")
    print(f"{Colors.GREEN}4.{Colors.END}  NoSQL Injection")
    print(f"{Colors.GREEN}5.{Colors.END}  Path Traversal")
    print(f"{Colors.GREEN}6.{Colors.END}  XXE - XML External Entity")
    print(f"{Colors.GREEN}7.{Colors.END}  SSRF")
    print(f"{Colors.GREEN}99.{Colors.END} {Colors.BOLD}FULL SCAN{Colors.END} (ALL tests with ALL payloads!)")
    print(f"{Colors.RED}0.{Colors.END}  Exit\n")

async def run_selected_tests(scanner, choices, websocket):
    """Run selected modern scanner checks."""
    checks = {
        "1": scanner.test_sql_injection_v2,
        "2": scanner.test_xss_v2,
        "3": scanner.test_command_injection_v2,
        "4": scanner.test_nosql_injection_v2,
        "5": scanner.test_path_traversal_v2,
        "6": scanner.test_xxe_v2,
        "7": scanner.test_ssrf_v2,
    }
    invalid = sorted(set(choices) - set(checks))
    if invalid:
        raise ValueError(f"Unknown test selection: {', '.join(invalid)}")
    for choice in choices:
        await checks[choice](websocket)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='wshawk-interactive',
        description='Run the interactive WSHawk scanner menu.',
    )
    parser.add_argument('--version', action='version', version=f'wshawk-interactive {__version__}')
    return parser


async def main(argv=None):
    build_parser().parse_args(argv)
    show_banner()
    
    # Get target URL
    print(f"{Colors.CYAN}Enter WebSocket URL:{Colors.END}")
    url = input(f"{Colors.YELLOW}> {Colors.END}").strip()
    
    if not url:
        Logger.error("No URL provided")
        return 2
    
    if not url.startswith(('ws://', 'wss://')):
        Logger.error("URL must start with ws:// or wss://")
        return 2
    
    # Show menu
    show_menu()
    
    # Get user choice
    print(f"{Colors.CYAN}Enter test numbers (comma-separated, e.g., 1,2,3 or 99 for all):{Colors.END}")
    choice = input(f"{Colors.YELLOW}> {Colors.END}").strip()
    
    if choice == '0':
        print(f"{Colors.YELLOW}Exiting...{Colors.END}")
        return 0
    
    # Parse choices
    choices = [c.strip() for c in choice.split(',')]
    
    if '99' in choices:
        Logger.warning("FULL SCAN mode - running ALL tests!")
        Logger.warning("This may take several minutes...")
    
    # Use advanced scanner_v2
    from .scanner_v2 import WSHawkV2
    
    Logger.info(f"Target: {url}")
    Logger.info(f"Using WSHawk v{__version__} Advanced Scanner")
    
    scanner = WSHawkV2(url, max_rps=10)
    scanner.use_headless_browser = False  # Disable by default
    scanner.use_oast = True
    
    # Run selected tests or full heuristic scan
    if '99' in choices:
        # Full scan: use the heuristic scan pipeline (all advanced features)
        await scanner.run_heuristic_scan()
    else:
        # Individual tests: connect and run only what the user selected
        Logger.info(f"Running selected tests: {', '.join(choices)}")
        ws = await scanner.connect()
        if ws is None:
            return 1
        try:
            await run_selected_tests(scanner, choices, ws)
        except (OSError, ValueError, RuntimeError) as e:
            Logger.error(f"Connection failed: {e}")
            return 1
        finally:
            await ws.close()
    
    Logger.success("Scan complete!")
    Logger.info(f"Vulnerabilities found: {len(scanner.vulnerabilities)}")
    
    # Show summary
    print()
    print("="*60)
    print("VULNERABILITY SUMMARY")
    print("="*60)
    if scanner.vulnerabilities:
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = sum(1 for v in scanner.vulnerabilities if v.get('confidence') == level)
            if count > 0:
                print(f"{level}: {count}")
    else:
        print("No vulnerabilities found")
    
    print("="*60)
    return 0 if scanner.scan_completed or '99' not in choices else 1


def cli(argv=None):
    """Entry point for pip-installed command"""
    try:
        return asyncio.run(main(argv))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        return 130
    except Exception as e:
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.END}")
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
