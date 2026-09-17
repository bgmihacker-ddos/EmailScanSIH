import asyncio
import time
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        page.on("console", lambda msg: print(f"[CONSOLE {msg.type.upper()}] {msg.text}"))
        page.on("pageerror", lambda err: print(f"[PAGE ERROR] {err}"))

        print("1. Navigating to signup...")
        await page.goto("http://localhost:5173/signup")
        await page.wait_for_load_state("networkidle")

        ts = int(time.time())
        email = f"forensic_analyst_{ts}@test.local"
        password = "Password123!@#"

        await page.fill('input[type="email"]', email)
        await page.fill('input[type="password"]', password)
        name_input = await page.query_selector('input[name="fullName"], input[name="name"], input[placeholder*="Name" i], input[type="text"]')
        if name_input:
            await name_input.fill("Forensic Analyst")

        # In Signup, there is confirmPassword
        confirm_pw = await page.query_selector('input[placeholder*="Confirm" i], input[name="confirmPassword"]')
        if confirm_pw:
            await confirm_pw.fill(password)

        await page.click('button[type="submit"]')

        # Wait for redirect to login
        for i in range(10):
            await page.wait_for_timeout(500)
            if "/login" in page.url:
                break
        print(f"2. Current URL after signup: {page.url}")

        if "/login" in page.url:
             print("2b. Navigating login...")
             await page.fill('input[type="email"]', email)
             await page.fill('input[type="password"]', password)
             await page.click('button[type="submit"]')
             for i in range(10):
                await page.wait_for_timeout(500)
                if "/dashboard" in page.url or "/analyze" in page.url:
                    break
             print(f"2c. URL after login: {page.url}")

        print("3. Navigating to /analyze...")
        await page.goto("http://localhost:5173/analyze")
        await page.wait_for_selector("textarea")
        print("4. On /analyze page.")

        test_email = """Delivered-To: victim@enterprise.corp
Received: from mail.attacker.net (mail.attacker.net [198.51.100.24])
    by mx.google.com with ESMTPS id abc123xyz
    for <victim@enterprise.corp>;
    Tue, 08 Sep 2026 10:00:00 +0000
Authentication-Results: mx.google.com;
    spf=fail (google.com: domain does not designate 198.51.100.24)
From: "Security Alert" <security@update-service.com>
To: victim@enterprise.corp
Subject: Urgent: Verify Account Access Immediately
Date: Tue, 08 Sep 2026 10:00:00 +0000
Content-Type: text/html; charset="UTF-8"

Please verify your credentials at http://suspicious-login-portal.com/login"""

        await page.fill("textarea", test_email)

        submit_btn = await page.query_selector('button:has-text("EXECUTE FORENSIC ANALYSIS")')
        if not submit_btn:
            print("ERROR: Submit button not found")
            return

        print("5. Submitting analysis...")
        await submit_btn.click()

        redirected = False
        for i in range(40):
            await page.wait_for_timeout(500)
            url = page.url
            if "/analysis/" in url:
                print(f"6. Successfully redirected to result page: {url}")
                redirected = True
                break

            progress_elem = await page.query_selector(".text-cyan-200")
            if progress_elem:
                text = await progress_elem.inner_text()
                pct_elem = await page.query_selector(".text-gray-400")
                pct_text = await pct_elem.inner_text() if pct_elem else ""
                print(f"   [POLL {i*0.5}s] Stage: {text} | {pct_text}")

        if not redirected:
            print(f"FAILED TO REDIRECT in 20s. Final URL: {page.url}")
            error_el = await page.query_selector('[role="alert"]')
            if error_el:
                print(f"UI Error displayed: {await error_el.inner_text()}")

        await page.wait_for_timeout(3000)
        print(f"7. Final Page URL: {page.url}")

        headings = await page.query_selector_all("h1, h2, h3")
        for h in headings:
            txt = await h.inner_text()
            if txt.strip():
                print(f"   Heading: {txt.strip()}")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
