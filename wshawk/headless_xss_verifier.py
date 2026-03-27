#!/usr/bin/env python3
"""
WSHawk Headless Browser XSS Verifier
Uses Playwright to collect sandboxed browser execution evidence
"""

import asyncio
try:
    from playwright.async_api import async_playwright, Browser, Page
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    async_playwright = None
    Browser = None
    Page = None
from typing import Optional, Tuple
import hashlib
import time

class HeadlessBrowserXSSVerifier:
    """
    Verifies XSS execution using headless browser
    """
    
    def __init__(self):
        self.browser: Optional[Browser] = None
        self.playwright = None
        self.execution_detected = False
        self.alert_text = None
        
    async def start(self):
        """Start headless browser"""
        if not HAS_PLAYWRIGHT:
            raise ImportError(
                "Playwright is not installed. Install it with: "
                "pip install playwright && playwright install chromium"
            )
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
    
    async def stop(self):
        """Stop headless browser"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def verify_xss_execution(self, html_content: str, payload: str, timeout: int = 5) -> Tuple[bool, str]:
        """
        Verify if XSS payload actually executes in browser
        
        Returns:
            (is_executed, evidence)
        """
        if not self.browser:
            await self.start()
        
        try:
            # Create new page
            page = await self.browser.new_page()
            
            # Set up alert handler
            alert_detected = False
            alert_message = ""
            
            async def handle_dialog(dialog):
                nonlocal alert_detected, alert_message
                alert_detected = True
                alert_message = dialog.message
                await dialog.dismiss()
            
            page.on("dialog", handle_dialog)
            
            # Set up console handler for detection
            console_messages = []
            
            def handle_console(msg):
                console_messages.append(msg.text)
            
            page.on("console", handle_console)
            
            # Create HTML page with WebSocket echo
            test_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>XSS Test</title>
            </head>
            <body>
                <div id="output">{html_content}</div>
                <script>
                    // Beacon for XSS detection
                    window.xssExecuted = false;
                    
                    // Override alert to set beacon
                    const originalAlert = window.alert;
                    window.alert = function(msg) {{
                        window.xssExecuted = true;
                        window.xssMessage = msg;
                        originalAlert(msg);
                    }};
                    
                    // Check for DOM-based execution
                    setTimeout(() => {{
                        if (window.xssExecuted) {{
                            console.log('XSS_EXECUTED: ' + window.xssMessage);
                        }}
                    }}, 100);
                </script>
            </body>
            </html>
            """
            
            # Load the page
            await page.set_content(test_html)
            
            # Wait for potential execution
            await asyncio.sleep(1)
            
            # Check if XSS executed
            xss_executed = await page.evaluate("window.xssExecuted || false")
            
            # Close page
            await page.close()
            
            if alert_detected:
                return (True, f"Alert executed: {alert_message}")
            elif xss_executed:
                return (True, "XSS beacon triggered")
            elif any('XSS_EXECUTED' in msg for msg in console_messages):
                return (True, "Console execution detected")
            else:
                return (False, "No execution detected")
        
        except Exception as e:
            return (False, f"Browser error: {str(e)}")
    
    async def verify_dom_mutation(self, html_content: str, payload: str) -> Tuple[bool, str]:
        """
        Verify if payload causes DOM mutations
        """
        if not self.browser:
            await self.start()
        
        try:
            page = await self.browser.new_page()
            
            # Set content
            await page.set_content(f"<html><body><div id='test'>{html_content}</div></body></html>")
            
            # Check for script tags
            script_count = await page.evaluate("document.querySelectorAll('script').length")
            
            # Check for event handlers
            has_event_handlers = await page.evaluate("""
                () => {
                    const elements = document.querySelectorAll('*');
                    for (let el of elements) {
                        for (let attr of el.attributes) {
                            if (attr.name.startsWith('on')) {
                                return true;
                            }
                        }
                    }
                    return false;
                }
            """)
            
            await page.close()
            
            if script_count > 0:
                return (True, f"Injected {script_count} script tag(s)")
            elif has_event_handlers:
                return (True, "Injected event handler(s)")
            else:
                return (False, "No DOM mutations detected")
        
        except Exception as e:
            return (False, f"DOM check error: {str(e)}")


# Standalone test
async def test_browser_verifier():
    """Test the headless browser verifier"""
    print("Testing Headless Browser XSS Verifier...")
    
    verifier = HeadlessBrowserXSSVerifier()
    await verifier.start()
    
    # Test 1: Alert-based XSS
    test_cases = [
        ("<script>alert('XSS')</script>", "<script>alert('XSS')</script>", True),
        ("<img src=x onerror=alert(1)>", "<img src=x onerror=alert(1)>", True),
        ("<div>safe content</div>", "safe", False),
        ("&lt;script&gt;alert(1)&lt;/script&gt;", "<script>alert(1)</script>", False),  # Encoded
    ]
    
    for html, payload, should_execute in test_cases:
        is_executed, evidence = await verifier.verify_xss_execution(html, payload)
        status = "✓" if is_executed == should_execute else "✗"
        print(f"{status} Payload: {payload[:50]}")
        print(f"  Executed: {is_executed}, Evidence: {evidence}")
    
    await verifier.stop()
    print("\nTest complete!")

if __name__ == "__main__":
    asyncio.run(test_browser_verifier())
