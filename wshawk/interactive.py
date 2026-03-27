#!/usr/bin/env python3
"""
WSHawk Interactive Menu
"""

import asyncio
from .__main__ import WSHawk, Logger, Colors

def show_banner():
    Logger.banner()
    
def show_menu():
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Select Tests to Run:{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}\n")
    
    print(f"{Colors.GREEN}1.{Colors.END}  Origin Validation Bypass - CSWSH (60+ payloads)")
    print(f"{Colors.GREEN}2.{Colors.END}  SQL Injection (ALL 722 payloads)")
    print(f"{Colors.GREEN}3.{Colors.END}  XSS - Cross-Site Scripting (ALL 7,106 payloads)")
    print(f"{Colors.GREEN}4.{Colors.END}  Command Injection (ALL 8,562 payloads)")
    print(f"{Colors.GREEN}5.{Colors.END}  NoSQL Injection (ALL payloads)")
    print(f"{Colors.GREEN}6.{Colors.END}  LDAP Injection (ALL payloads)")
    print(f"{Colors.GREEN}7.{Colors.END}  Path Traversal (ALL payloads)")
    print(f"{Colors.GREEN}8.{Colors.END}  SSTI - Server Side Template Injection (ALL payloads)")
    print(f"{Colors.GREEN}9.{Colors.END}  XXE - XML External Entity (ALL payloads)")
    print(f"{Colors.GREEN}10.{Colors.END} Open Redirect (ALL payloads)")
    print(f"{Colors.GREEN}11.{Colors.END} Message Replay Attack")
    print(f"{Colors.GREEN}12.{Colors.END} Rate Limiting Test")
    print(f"{Colors.GREEN}13.{Colors.END} Authentication Bypass")
    print(f"{Colors.GREEN}99.{Colors.END} {Colors.BOLD}FULL SCAN{Colors.END} (ALL tests with ALL payloads!)")
    print(f"{Colors.RED}0.{Colors.END}  Exit\n")

async def run_selected_tests(scanner, choices):
    """Run only selected tests"""
    
    if '1' in choices or '99' in choices:
        await scanner.test_origin_bypass()
    
    if '2' in choices or '99' in choices:
        await scanner.test_sql_injection()
    
    if '3' in choices or '99' in choices:
        await scanner.test_xss()
    
    if '4' in choices or '99' in choices:
        await scanner.test_command_injection()
    
    if '5' in choices or '99' in choices:
        await scanner.test_nosql_injection()
    
    if '6' in choices or '99' in choices:
        await scanner.test_ldap_injection()
    
    if '7' in choices or '99' in choices:
        await scanner.test_path_traversal()
    
    if '8' in choices or '99' in choices:
        await scanner.test_ssti()
    
    if '9' in choices or '99' in choices:
        await scanner.test_xxe()
    
    if '10' in choices or '99' in choices:
        await scanner.test_open_redirect()
    
    if '11' in choices or '99' in choices:
        await scanner.test_message_replay()
    
    if '12' in choices or '99' in choices:
        await scanner.test_rate_limiting()
    
    if '13' in choices or '99' in choices:
        await scanner.test_authentication_bypass()

async def main():
    show_banner()
    
    # Get target URL
    print(f"{Colors.CYAN}Enter WebSocket URL:{Colors.END}")
    url = input(f"{Colors.YELLOW}> {Colors.END}").strip()
    
    if not url:
        Logger.error("No URL provided")
        return
    
    if not url.startswith(('ws://', 'wss://')):
        Logger.error("URL must start with ws:// or wss://")
        return
    
    # Show menu
    show_menu()
    
    # Get user choice
    print(f"{Colors.CYAN}Enter test numbers (comma-separated, e.g., 1,2,3 or 99 for all):{Colors.END}")
    choice = input(f"{Colors.YELLOW}> {Colors.END}").strip()
    
    if choice == '0':
        print(f"{Colors.YELLOW}Exiting...{Colors.END}")
        return
    
    # Parse choices
    choices = [c.strip() for c in choice.split(',')]
    
    if '99' in choices:
        Logger.warning("FULL SCAN mode - running ALL tests!")
        Logger.warning("This may take several minutes...")
    
    # Use advanced scanner_v2
    from .scanner_v2 import WSHawkV2
    
    Logger.info(f"Target: {url}")
    Logger.info("Using WSHawk v4.0.0 Advanced Scanner")
    
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
        try:
            import websockets
            async with websockets.connect(url) as ws:
                await run_selected_tests(scanner, choices)
        except Exception as e:
            Logger.error(f"Connection failed: {e}")
            return
    
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


def cli():
    """Entry point for pip-installed command"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Fatal error: {e}{Colors.END}")


if __name__ == "__main__":
    cli()
