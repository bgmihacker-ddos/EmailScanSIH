"""Populate backend database and docs/eml with diverse real-world, mixed, and alarm-genuine emails.

Categories:
1. "Alarm-Looking but 100% Genuine" (Security alerts, fraud warnings, billing notices with valid SPF/DKIM/DMARC)
2. "Real Mixed / Stealthy Phishing & BEC" (Typosquatting, BEC wire change, disguised attachments, quishing)
3. "Diverse Real-World Human Emails" (Sampled from human_legit.csv and human_phishing.csv)
"""

import asyncio
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
from sqlalchemy import text

from app.database.session import SessionLocal
from app.api.routes.analysis import _execute_analysis_pipeline
from app.models.analysis import AnalysisResult


DOCS_EML_DIR = Path(__file__).resolve().parents[2] / "docs" / "eml"
DOCS_EML_DIR.mkdir(parents=True, exist_ok=True)
DATASET_DIR = Path(__file__).resolve().parents[2] / "docs" / "dataset"

# ---------------------------------------------------------------------------
# 1. "LOOKS FRAUDULENT / ALARMING BUT 100% GENUINE" TEMPLATES
# ---------------------------------------------------------------------------
GENUINE_ALARM_TEMPLATES = [
    {
        "filename": "alarm_legit_google_new_signin.eml",
        "from": '"Google Accounts" <no-reply@accounts.google.com>',
        "to": "user@enterprise.org",
        "subject": "Security alert: New sign-in from Chrome on Windows 11",
        "ip": "209.85.220.41",
        "spf_domain": "accounts.google.com",
        "dkim_domain": "google.com",
        "body": """Your Google Account was just signed in to from a new Windows 11 device.

Location: Frankfurt, Germany
Browser: Chrome 128.0.0
IP Address: 84.115.22.19

If this was you, you don't need to do anything.
If this wasn't you, your account may be compromised. Check activity and secure your account immediately:
https://myaccount.google.com/notifications

Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043""",
    },
    {
        "filename": "alarm_legit_github_pat_expired.eml",
        "from": '"GitHub Security" <notifications@github.com>',
        "to": "dev@enterprise.org",
        "subject": "[GitHub] Security notice: Personal access token 'prod-deploy-key' expired",
        "ip": "192.30.252.204",
        "spf_domain": "github.com",
        "dkim_domain": "github.com",
        "body": """Hi Developer,

Your personal access token 'prod-deploy-key' (ID: pat_992140a) has expired as of today.

Any automated CI/CD workflows or script deployments utilizing this credential will begin failing with HTTP 401 Unauthorized.

To revoke or regenerate this token, navigate to your security settings:
https://github.com/settings/tokens

Never share your personal access tokens or commit them to public repositories.

Thanks,
The GitHub Security Team""",
    },
    {
        "filename": "alarm_legit_chase_fraud_alert.eml",
        "from": '"Chase Fraud Protection" <fraud-alerts@chase.com>',
        "to": "cardholder@enterprise.org",
        "subject": "Urgent: Unusual activity on card ending in 8192",
        "ip": "159.53.110.12",
        "spf_domain": "chase.com",
        "dkim_domain": "chase.com",
        "body": """Chase Fraud Protection Services

We detected a potentially fraudulent charge of $489.20 at BESTBUY ONLINE on card ending in 8192.

Date/Time: Sep 16, 2026 14:22 EST
Status: Pending verification

Did you authorize this transaction?
Please sign in to Chase Mobile or your online dashboard to confirm or dispute:
https://www.chase.com/secure/fraud-verify

If you did not authorize this transaction, your card will be blocked immediately and a replacement issued.

JPMorgan Chase Bank, N.A. Member FDIC.""",
    },
    {
        "filename": "alarm_legit_apple_icloud_login.eml",
        "from": '"Apple Support" <noreply@email.apple.com>',
        "to": "user@enterprise.org",
        "subject": "Your Apple ID was used to sign in to iCloud via a web browser",
        "ip": "17.171.37.12",
        "spf_domain": "email.apple.com",
        "dkim_domain": "email.apple.com",
        "body": """Dear Customer,

Your Apple ID was used to sign in to iCloud via a web browser.

Date and Time: September 16, 2026, 09:41 AM GMT
Operating System: macOS Sequoia

If you recently signed in, you can disregard this email.

If you have not signed in to iCloud recently and believe someone may have accessed your account, go to Apple ID to reset your password:
https://appleid.apple.com

Apple Support""",
    },
    {
        "filename": "alarm_legit_netflix_billing_retry.eml",
        "from": '"Netflix Support" <info@mailer.netflix.com>',
        "to": "subscriber@enterprise.org",
        "subject": "Action Required: Update payment method to maintain membership",
        "ip": "198.2.138.10",
        "spf_domain": "mailer.netflix.com",
        "dkim_domain": "netflix.com",
        "body": """We were unable to process your payment for your next billing cycle.

Please update your credit or debit card details to continue watching your favorite shows without interruption.

Update Account:
https://www.netflix.com/YourAccountPayment

We're here to help if you need it. Visit the Help Center for more info.
The Netflix Team""",
    },
    {
        "filename": "alarm_legit_aws_quota_exceeded.eml",
        "from": '"Amazon Web Services" <no-reply-aws@amazon.com>',
        "to": "sysadmin@enterprise.org",
        "subject": "AWS CloudWatch Alarm: EC2 CPUUtilization > 95% in us-east-1",
        "ip": "54.240.11.2",
        "spf_domain": "amazon.com",
        "dkim_domain": "amazon.com",
        "body": """You are receiving this email because your Amazon CloudWatch Alarm "Prod-Web-CPU-Critical" in the US East (N. Virginia) region entered the ALARM state.

Reason for State Change: Threshold Crossed: 1 out of 1 datapoints [97.8%] was greater than the threshold (95.0%).
Alarm Details:
- Name: Prod-Web-CPU-Critical
- Metric: CPUUtilization
- Namespace: AWS/EC2

View in AWS Management Console:
https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#alarmsV2:alarm/Prod-Web-CPU-Critical

Amazon Web Services, Inc.""",
    },
    {
        "filename": "alarm_legit_stripe_payout_hold.eml",
        "from": '"Stripe Support" <support@stripe.com>',
        "to": "finance@enterprise.org",
        "subject": "Action needed: Identity verification required to resume payouts",
        "ip": "199.255.192.14",
        "spf_domain": "stripe.com",
        "dkim_domain": "stripe.com",
        "body": """Hello,

Due to updated financial regulations (FinCEN CDD rule), we need to re-verify the beneficial ownership information for your Stripe account.

Payouts to your bank account are currently paused until this information is confirmed. Your ability to accept card payments from customers is not affected.

Please submit your verification documents securely through your Stripe Dashboard:
https://dashboard.stripe.com/verify

Thanks,
The Stripe Team""",
    },
    {
        "filename": "alarm_legit_microsoft_unusual_signin.eml",
        "from": '"Microsoft account team" <account-security-noreply@accountprotection.microsoft.com>',
        "to": "employee@enterprise.org",
        "subject": "Microsoft account unusual sign-in activity",
        "ip": "65.55.234.20",
        "spf_domain": "accountprotection.microsoft.com",
        "dkim_domain": "microsoft.com",
        "body": """We detected something unusual about a recent sign-in to the Microsoft account.

Sign-in details:
Country/region: Russia
IP address: 185.220.101.5
Date: 9/16/2026 8:15 AM (UTC)
Platform: Windows

If this was you, you can safely ignore this email.
If you're not sure this was you, a malicious user might have your password. Please review your recent activity and secure your account:
https://account.live.com/Activity

To opt out or change where you receive security notifications, click here.
Thanks,
The Microsoft account team""",
    },
    {
        "filename": "alarm_legit_slack_new_device.eml",
        "from": '"Slack" <feedback@slack.com>',
        "to": "colleague@enterprise.org",
        "subject": "New sign-in to Slack from Safari on iOS",
        "ip": "54.240.35.4",
        "spf_domain": "slack.com",
        "dkim_domain": "slack.com",
        "body": """Your Slack account was recently signed in to from a new device:

Device: Safari on iOS 18
Location: London, United Kingdom
IP: 82.165.197.1

If this was you, you're all set! No action is needed.
If this wasn't you, we strongly recommend signing out of all sessions and resetting your password:
https://slack.com/account/settings

Stay safe,
The team at Slack""",
    },
    {
        "filename": "alarm_legit_paypal_security_code.eml",
        "from": '"PayPal" <service@paypal.com>',
        "to": "merchant@enterprise.org",
        "subject": "Your PayPal security code is 492015",
        "ip": "173.0.84.225",
        "spf_domain": "paypal.com",
        "dkim_domain": "paypal.com",
        "body": """Your security code is: 492015

This code expires in 10 minutes. Please enter it in your browser window to complete your sign-in.

Never share this code with anyone over phone or email. PayPal employees will never ask for your security code.

If you did not request this code, please secure your PayPal account immediately:
https://www.paypal.com/myaccount/security

PayPal, Inc.""",
    },
    {
        "filename": "alarm_legit_cloudflare_under_attack.eml",
        "from": '"Cloudflare Automated Alerts" <no-reply@cloudflare.com>',
        "to": "devops@enterprise.org",
        "subject": "[Cloudflare] HTTP DDoS attack automatically mitigated on zone enterprise.org",
        "ip": "198.41.200.10",
        "spf_domain": "cloudflare.com",
        "dkim_domain": "cloudflare.com",
        "body": """Cloudflare DDoS Protection Notification

Between 11:30 UTC and 11:45 UTC, our automated edge mitigation systems detected and mitigated an HTTP DDoS attack targeting your zone enterprise.org.

Peak Traffic: 1.4 Million Requests / Second
Mitigation Action: Layer 7 Adaptive Rate Limiting & Managed Challenge
Origin Impact: 0% degraded (Origin traffic remained nominal)

View attack analytics and security logs in your dashboard:
https://dash.cloudflare.com/analytics/security

Cloudflare Operations""",
    },
    {
        "filename": "alarm_legit_vercel_failed_build.eml",
        "from": '"Vercel" <notifications@vercel.com>',
        "to": "frontend-team@enterprise.org",
        "subject": "[Vercel] Deployment failed for project 'email-threat-ui' (commit #88a21e)",
        "ip": "198.2.186.24",
        "spf_domain": "vercel.com",
        "dkim_domain": "vercel.com",
        "body": """Deployment Error: Command 'npm run build' exited with code 1.

Project: email-threat-ui
Branch: main
Commit: 88a21e (chore: sync production dependencies)

Error Summary:
Type error: Property 'evidence_graph' does not exist on type 'AnalysisResult'.

Inspect deployment logs:
https://vercel.com/enterprise-org/email-threat-ui/deployments/dpl_992140a

Vercel Team""",
    },
]

# Generate more variations of legitimate alarms across services
EXTRA_GENUINE_SERVICES = [
    ("Zoom", "no-reply@zoom.us", "zoom.us", "Your scheduled cloud recording is ready for viewing", "https://zoom.us/rec/share/8821094"),
    ("Atlassian", "jira@atlassian.net", "atlassian.net", "Security: Admin permissions granted to service-account-prod", "https://enterprise.atlassian.net/admin"),
    ("Dropbox", "no-reply@dropbox.com", "dropbox.com", "Your Dropbox storage is 92% full - upgrade or delete files", "https://www.dropbox.com/account/plan"),
    ("LinkedIn", "security-noreply@linkedin.com", "linkedin.com", "Your LinkedIn password was changed successfully", "https://www.linkedin.com/psettings/security"),
    ("Docker", "notifications@docker.com", "docker.com", "Critical security vulnerability found in repository base-python:3.11", "https://hub.docker.com/security"),
    ("Steam", "noreply@steampowered.com", "steampowered.com", "Steam Guard: An access attempt was made from Tokyo, Japan", "https://help.steampowered.com"),
    ("Uber", "uber.us@uber.com", "uber.com", "Your Thursday evening ride with Uber ($34.12)", "https://riders.uber.com/trips"),
    ("Spotify", "no-reply@spotify.com", "spotify.com", "Your receipt for Spotify Premium Family plan", "https://www.spotify.com/account/subscription"),
    ("Supabase", "notifications@supabase.io", "supabase.io", "[Notice] Database migration completed on project 'auth-vault'", "https://app.supabase.com/project/auth-vault"),
    ("Sentry", "alerts@sentry.io", "sentry.io", "[Critical Alert] Unhandled exception surge: TypeError in auth.py", "https://sentry.io/organizations/enterprise/issues"),
    ("HDFC Bank", "alerts@hdfcbank.net", "hdfcbank.net", "Important: Update your NetBanking credentials before annual cycle", "https://netbanking.hdfcbank.com"),
    ("ICICI Bank", "creditcards@icicibank.com", "icicibank.com", "Transaction Alert: INR 4,500.00 spent on ICICI Credit Card xx1004", "https://www.icicibank.com/personal-banking"),
    ("State Bank of India", "no-reply@sbi.co.in", "sbi.co.in", "YONO SBI Security Notice: Mandatory device binding successful", "https://retail.onlinesbi.sbi"),
    ("GitLab", "gitlab@mg.gitlab.com", "gitlab.com", "[GitLab] Two-factor authentication recovery codes generated", "https://gitlab.com/-/profile/two_factor_auth"),
    ("Bitbucket", "notifications@bitbucket.org", "bitbucket.org", "Repository push rejected: secret token detected in git history", "https://bitbucket.org/enterprise/core-repo"),
    ("DigitalOcean", "support@digitalocean.com", "digitalocean.com", "Your droplet 'worker-node-01' has been restarted", "https://cloud.digitalocean.com/droplets"),
    ("Postmark", "support@postmarkapp.com", "postmarkapp.com", "Outbound bounce rate reached 1.2% on transactional stream", "https://account.postmarkapp.com/servers"),
    ("Figma", "notifications@figma.com", "figma.com", "Shared file access: SOC-Dashboard-Mockup was shared with you", "https://www.figma.com/file/soc-dashboard"),
]

for idx, (svc_name, sender, dom, subj, url) in enumerate(EXTRA_GENUINE_SERVICES):
    GENUINE_ALARM_TEMPLATES.append({
        "filename": f"alarm_legit_{svc_name.lower().replace(' ', '_')}_{idx}.eml",
        "from": f'"{svc_name} Security" <{sender}>',
        "to": f"team-member-{idx}@enterprise.org",
        "subject": subj,
        "ip": f"198.51.100.{10 + idx}",
        "spf_domain": dom,
        "dkim_domain": dom,
        "body": f"""Official notification from {svc_name}.

{subj}.

This automated security communication was generated to protect your enterprise account.
Please review your configuration or activity:
{url}

If you have questions, please reach out to our official verified support team.
{svc_name} Customer Trust & Security.""",
    })


# ---------------------------------------------------------------------------
# 2. "REAL MIXED / STEALTHY PHISHING & BEC" TEMPLATES
# ---------------------------------------------------------------------------
MIXED_STEALTHY_TEMPLATES = [
    {
        "filename": "mixed_typosquat_paypal_refund.eml",
        "from": '"PayPal Resolution Center" <billing-dispute@paypa1-support.com>',
        "to": "buyer@enterprise.org",
        "subject": "Dispute #PP-D-99120: Unauthorized transaction refund approved ($850.00)",
        "ip": "198.51.100.77",
        "spf_pass": False,
        "dkim_pass": False,
        "reply_to": "support@paypa1-support.com",
        "body": """PayPal Security & Resolution Center

Dear Customer,

We have placed an immediate hold on an unauthorized charge of $850.00 USD to 'Coinbase Cryptocurrencies Ltd'.

To finalize the dispute reversal and restore the funds into your checking account, you must confirm your transaction identification within 24 hours:
https://resolution.paypa1-support.com/dispute/resolve?case=PP-99120

Case Number: PP-D-99120
Status: Escalated

PayPal Anti-Fraud Division""",
    },
    {
        "filename": "mixed_typosquat_docusign_nda.eml",
        "from": '"DocuSign Secure Signer" <documents@docus1gn-review.net>',
        "to": "executive@enterprise.org",
        "subject": "Please DocuSign: Mutual Non-Disclosure Agreement & Vendor Terms",
        "ip": "192.0.2.88",
        "spf_pass": False,
        "dkim_pass": False,
        "reply_to": "reviewer@docus1gn-review.net",
        "body": """DocuSign Envelope ID: 88A41-99B20-1124C

Sarah Jenkins has sent you a document to review and sign.

Document: 2026_Enterprise_Vendor_Agreement.pdf
Pages: 14

Please review and sign this document before close of business today:
https://view.docus1gn-review.net/envelope/88A41?auth=sso

Do not share this email. The link is uniquely tied to your corporate signature authority.

Powered by DocuSign""",
    },
    {
        "filename": "mixed_bec_ceo_urgent_wire.eml",
        "from": '"Robert Vance - Chief Executive Officer" <robert.vance@enterprise-corp.com>',
        "to": "finance-lead@enterprise-corp.com",
        "subject": "Confidential / Time-Sensitive: Project Apex Closing Remittance",
        "ip": "203.0.113.45",
        "spf_pass": True,
        "dkim_pass": False,
        "reply_to": "robert.vance.exec@mail-forwarding.org",
        "body": """Good afternoon,

I am currently in an all-day confidential board meeting for our Q4 acquisition (Project Apex) and cannot take phone calls.

We need to wire the initial escrow closing deposit of $78,400.00 USD before the 4:00 PM cutoff today.

Please confirm that you are at your desk so I can send through the beneficiary bank coordinates and authorization code immediately. This acquisition is strictly confidential under NDA until our formal press release on Monday.

Best regards,

Robert Vance
Chief Executive Officer
Enterprise Corp""",
    },
    {
        "filename": "mixed_bec_payroll_direct_deposit.eml",
        "from": '"David Miller" <david.miller@enterprise-corp.com>',
        "to": "payroll@enterprise-corp.com",
        "subject": "Update direct deposit account for next pay cycle",
        "ip": "198.51.100.91",
        "spf_pass": True,
        "dkim_pass": False,
        "reply_to": "david.miller.personal@webmail-portal.com",
        "body": """Hello Payroll Team,

I recently changed my primary checking account due to a branch closure.

Could you please update my direct deposit allocation for the upcoming paycheck? I have attached the revised routing details:

Bank: Cross River Bank
Routing (ABA): 021214891
Account: 991204812394
Account Type: Checking

Can this change take effect for this Friday's distribution? Please let me know if you need any additional voided check documents.

Thank you,
David Miller
Senior Software Architect""",
    },
    {
        "filename": "mixed_attachment_invoice_double_ext.eml",
        "from": '"Catering & Facilities Billing" <invoices@facilities-management.org>',
        "to": "office-manager@enterprise.org",
        "subject": "Overdue Balance: Corporate Catering Invoice #CAT-9921",
        "ip": "198.51.100.102",
        "spf_pass": False,
        "dkim_pass": False,
        "attachment": ("Invoice_9921_Details.pdf.exe", b"MZ\x90\x00\x03\x00\x00\x00This program cannot be run in DOS mode."),
        "body": """Dear Accounts Payable,

Please find attached the itemized invoice #CAT-9921 for last month's executive luncheon.

Our records indicate that payment of $2,340.00 is currently 15 days past due. Please review the attached breakdown and remit payment via ACH or corporate card.

Invoice Attachment: Invoice_9921_Details.pdf.exe

Thank you for your prompt attention.
Facilities Management Group""",
    },
    {
        "filename": "mixed_quishing_mfa_qr_code.eml",
        "from": '"IT Security Helpdesk" <support@it-security-portal.net>',
        "to": "all-staff@enterprise.org",
        "subject": "Action Required: Scan QR code to bind new Authenticator app",
        "ip": "203.0.113.88",
        "spf_pass": False,
        "dkim_pass": False,
        "body": """Enterprise IT Security Bulletin

All staff members are required to migrate their two-factor authentication profile to the new Microsoft Authenticator standard.

Instructions:
1. Open your mobile device camera.
2. Scan the secure corporate QR code below:
   [QR CODE IMAGE: https://login.microsoft-sso-portal.cc/qr/auth-token-99120]
3. Approve the push notification to complete enrollment.

Failure to complete this binding by 5:00 PM will result in network access restriction.

Corporate IT Infrastructure Team""",
    },
]

# Generate more mixed / lookalike variations
MIXED_BRANDS = [
    ("Bank of America", "fraud@bank0famerica-support.com", "bank0famerica-support.com", "Urgent security update required for online banking access", "https://bank0famerica-support.com/auth/verify"),
    ("Amazon Web", "billing@amaz0n-cloud-services.org", "amaz0n-cloud-services.org", "Suspension Notice: Outstanding balance of $3,420.00 on AWS tenant", "https://amaz0n-cloud-services.org/settle-balance"),
    ("Wells Fargo", "notifications@wellsfarg0-online.net", "wellsfarg0-online.net", "Wire transfer #WF-8891 awaiting your telephonic confirmation", "https://wellsfarg0-online.net/confirm-wire"),
    ("DocuSign", "signer@docusign-contracts-sign.cc", "docusign-contracts-sign.cc", "Immediate signature requested: Separation and Release Agreement", "https://docusign-contracts-sign.cc/review/doc991"),
    ("Google Workspace", "admin@g00gle-workspace-admin.com", "g00gle-workspace-admin.com", "Your Google Workspace business subscription has expired", "https://g00gle-workspace-admin.com/renew-license"),
    ("Microsoft Office", "security@office365-tenant-portal.org", "office365-tenant-portal.org", "Undelivered incoming emails held in quarantine queue", "https://office365-tenant-portal.org/quarantine/release"),
    ("Dropbox", "share@dr0pbox-file-transfer.info", "dr0pbox-file-transfer.info", "You have received 3 confidential files from Senior Management", "https://dr0pbox-file-transfer.info/download?id=99214"),
    ("Zoom Video", "invitations@z00m-conferences.us", "z00m-conferences.us", "Urgent executive all-hands conference link has changed", "https://z00m-conferences.us/j/992140192"),
    ("Adobe Creative", "licensing@ad0be-creative-cloud.net", "ad0be-creative-cloud.net", "Your Adobe Enterprise license key will terminate in 48 hours", "https://ad0be-creative-cloud.net/activate-key"),
    ("Stripe Payments", "payouts@str1pe-merchants.com", "str1pe-merchants.com", "Urgent: Payout of $14,290.00 failed due to bank verification error", "https://str1pe-merchants.com/verify-bank-details"),
    ("DHL Express", "tracking@dhl-package-reschedule.com", "dhl-package-reschedule.com", "Delivery Exception: Customs duties unpaid for parcel #DHL-991204", "https://dhl-package-reschedule.com/pay-duties"),
    ("FedEx Ground", "delivery@fedx-express-tracking.net", "fedx-express-tracking.net", "Your scheduled delivery could not be completed - update address", "https://fedx-express-tracking.net/redelivery"),
    ("Intuit QuickBooks", "invoices@quickb00ks-accounting.org", "quickb00ks-accounting.org", "New electronic invoice received from Miller Supplies ($12,450.00)", "https://quickb00ks-accounting.org/invoices/pay"),
    ("Salesforce", "alerts@salesf0rce-sso.com", "salesf0rce-sso.com", "Security Token Expiration: Reset your security credentials", "https://salesf0rce-sso.com/token-reset"),
    ("GitLab", "support@g1tlab-ci-cd.org", "g1tlab-ci-cd.org", "Your pipeline quota exceeded: update billing card immediately", "https://g1tlab-ci-cd.org/billing/update"),
    ("Kroll Cyber", "investigations@kr0ll-incident-response.com", "kr0ll-incident-response.com", "Subpoena & Evidence Preservation Notice: Incident #CY-2026-99", "https://kr0ll-incident-response.com/evidence/upload"),
    ("Coinbase", "compliance@c0inbase-compliance.net", "c0inbase-compliance.net", "Mandatory KYC update required to unlock ETH withdrawal", "https://c0inbase-compliance.net/kyc/upload"),
    ("Meta Business", "appeals@meta-ads-compliance.cc", "meta-ads-compliance.cc", "Your Meta Ad Account has been scheduled for permanent deletion", "https://meta-ads-compliance.cc/appeal/form"),
    ("Internal IT", "admin@corp-internal-it.info", "corp-internal-it.info", "Mandatory Windows Patch: Install corporate root certificate", "https://corp-internal-it.info/certs/install.bat"),
    ("HR Portal", "benefits@workday-benefits-online.org", "workday-benefits-online.org", "Important: Review your 2026 Bonus calculation sheet", "https://workday-benefits-online.org/bonus/sheet"),
]

for idx, (brand, sender, dom, subj, url) in enumerate(MIXED_BRANDS):
    MIXED_STEALTHY_TEMPLATES.append({
        "filename": f"mixed_stealth_{brand.lower().replace(' ', '_')}_{idx}.eml",
        "from": f'"{brand} Service" <{sender}>',
        "to": f"victim-{idx}@enterprise.org",
        "subject": subj,
        "ip": f"203.0.113.{20 + idx}",
        "spf_pass": False,
        "dkim_pass": False,
        "reply_to": f"reply-{idx}@{dom}",
        "body": f"""Notice from {brand}.

{subj}.

To protect your access and avoid immediate service interruption, please access the portal below:
{url}

Reference ID: REF-{idx*1000 + 4920}
Timestamp: {datetime.now(timezone.utc).isoformat()}

{brand} Automated Customer Operations""",
    })


# ---------------------------------------------------------------------------
# EML BUILDER HELPER
# ---------------------------------------------------------------------------
def build_raw_eml(
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
    date_dt: datetime,
    spf_pass: bool = True,
    dkim_pass: bool = True,
    dmarc_pass: bool = True,
    client_ip: str = "209.85.220.41",
    spf_domain: str = "example.com",
    dkim_domain: str = "example.com",
    reply_to: str = None,
    attachment: Tuple[str, bytes] = None,
) -> bytes:
    msg_id = f"<{uuid.uuid4()}@{spf_domain}>"
    date_str = date_dt.strftime("%a, %d %b %Y %H:%M:%S +0000")

    spf_str = "pass" if spf_pass else "softfail"
    dkim_str = "pass" if dkim_pass else "fail"
    dmarc_str = "pass" if dmarc_pass else "fail"

    lines = [
        f"Return-Path: <{from_addr}>",
        f"Delivered-To: {to_addr}",
        f"Received: from mail.{spf_domain} (mail.{spf_domain} [{client_ip}]) by mx.google.com with ESMTP id {uuid.uuid4().hex[:12]}; {date_str}",
        f"Received-SPF: {spf_str} ({spf_domain}: domain designates {client_ip} as permitted sender) client-ip={client_ip};",
        f"Authentication-Results: mx.google.com; spf={spf_str} smtp.mailfrom={spf_domain}; dkim={dkim_str} header.i=@{dkim_domain}; dmarc={dmarc_str} header.from={spf_domain}",
        f"From: {from_addr}",
        f"To: {to_addr}",
        f"Subject: {subject}",
        f"Date: {date_str}",
        f"Message-ID: {msg_id}",
    ]
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")

    lines.append("MIME-Version: 1.0")

    if attachment:
        att_name, att_data = attachment
        boundary = f"----=_Part_{uuid.uuid4().hex[:16]}"
        lines.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
        lines.append("")
        lines.append(f"--{boundary}")
        lines.append("Content-Type: text/plain; charset=UTF-8")
        lines.append("Content-Transfer-Encoding: 7bit")
        lines.append("")
        lines.append(body)
        lines.append("")
        lines.append(f"--{boundary}")
        lines.append(f'Content-Type: application/octet-stream; name="{att_name}"')
        lines.append("Content-Transfer-Encoding: base64")
        lines.append(f'Content-Disposition: attachment; filename="{att_name}"')
        lines.append("")
        import base64
        lines.append(base64.b64encode(att_data).decode("ascii"))
        lines.append(f"--{boundary}--")
    else:
        lines.append("Content-Type: text/plain; charset=UTF-8")
        lines.append("Content-Transfer-Encoding: 7bit")
        lines.append("")
        lines.append(body)

    return "\r\n".join(lines).encode("utf-8")


# ---------------------------------------------------------------------------
# MAIN POPULATION ROUTINE
# ---------------------------------------------------------------------------
async def main():
    print("=" * 75)
    print("STARTING DIVERSE EMAIL CORPUS POPULATION FOR SUPABASE SOC DASHBOARD")
    print("=" * 75)

    now = datetime.now(timezone.utc)

    # 1. Prepare genuine alarm emails
    tasks_to_run = []
    print(f"Generating {len(GENUINE_ALARM_TEMPLATES)} 'Look Alarming but 100% Genuine' emails...")
    for idx, item in enumerate(GENUINE_ALARM_TEMPLATES):
        # Stagger dates over the past 6 days
        days_ago = idx % 7
        hours_ago = random.randint(1, 23)
        dt = now - timedelta(days=days_ago, hours=hours_ago, minutes=random.randint(5, 55))

        raw = build_raw_eml(
            from_addr=item["from"],
            to_addr=item["to"],
            subject=item["subject"],
            body=item["body"],
            date_dt=dt,
            spf_pass=True,
            dkim_pass=True,
            dmarc_pass=True,
            client_ip=item["ip"],
            spf_domain=item["spf_domain"],
            dkim_domain=item["dkim_domain"],
        )
        # Save EML to docs/eml
        eml_file = DOCS_EML_DIR / item["filename"]
        eml_file.write_bytes(raw)
        tasks_to_run.append((item["filename"], raw, dt, "ALARM_GENUINE"))

    # 2. Prepare stealthy / mixed emails
    print(f"Generating {len(MIXED_STEALTHY_TEMPLATES)} 'Real Mixed / Stealthy Phishing & BEC' emails...")
    for idx, item in enumerate(MIXED_STEALTHY_TEMPLATES):
        days_ago = (idx + 2) % 7
        hours_ago = random.randint(1, 23)
        dt = now - timedelta(days=days_ago, hours=hours_ago, minutes=random.randint(5, 55))

        raw = build_raw_eml(
            from_addr=item["from"],
            to_addr=item["to"],
            subject=item["subject"],
            body=item["body"],
            date_dt=dt,
            spf_pass=item.get("spf_pass", False),
            dkim_pass=item.get("dkim_pass", False),
            dmarc_pass=False,
            client_ip=item.get("ip", "203.0.113.1"),
            spf_domain=item["from"].split("@")[-1].rstrip(">"),
            dkim_domain=item["from"].split("@")[-1].rstrip(">"),
            reply_to=item.get("reply_to"),
            attachment=item.get("attachment"),
        )
        eml_file = DOCS_EML_DIR / item["filename"]
        eml_file.write_bytes(raw)
        tasks_to_run.append((item["filename"], raw, dt, "MIXED_THREAT"))

    # 3. Load samples from human_legit.csv and human_phishing.csv
    human_legit_csv = DATASET_DIR / "human_legit.csv"
    human_phish_csv = DATASET_DIR / "human_phishing.csv"

    if human_legit_csv.exists():
        df_l = pd.read_csv(human_legit_csv).dropna(subset=["subject", "body"]).head(30)
        print(f"Sampling {len(df_l)} real benign emails from human_legit.csv...")
        for idx, row in df_l.iterrows():
            days_ago = idx % 7
            dt = now - timedelta(days=days_ago, hours=random.randint(1, 23), minutes=random.randint(5, 55))
            sender = str(row.get("sender") or "support@trusted-vendor.com")
            subj = str(row.get("subject") or "Routine business update")[:150]
            body = str(row.get("body") or "")[:2000]
            dom = sender.split("@")[-1].rstrip(">") if "@" in sender else "trusted-vendor.com"
            raw = build_raw_eml(
                from_addr=sender,
                to_addr="team@enterprise.org",
                subject=subj,
                body=body,
                date_dt=dt,
                spf_pass=True,
                dkim_pass=True,
                dmarc_pass=True,
                spf_domain=dom,
                dkim_domain=dom,
            )
            fname = f"human_legit_{idx}.eml"
            (DOCS_EML_DIR / fname).write_bytes(raw)
            tasks_to_run.append((fname, raw, dt, "HUMAN_LEGIT"))

    if human_phish_csv.exists():
        df_p = pd.read_csv(human_phish_csv).dropna(subset=["subject", "body"]).head(30)
        print(f"Sampling {len(df_p)} real phishing emails from human_phishing.csv...")
        for idx, row in df_p.iterrows():
            days_ago = (idx + 3) % 7
            dt = now - timedelta(days=days_ago, hours=random.randint(1, 23), minutes=random.randint(5, 55))
            sender = str(row.get("sender") or "security-verify@account-update.net")
            subj = str(row.get("subject") or "Action required on your account")[:150]
            body = str(row.get("body") or "")[:2000]
            dom = sender.split("@")[-1].rstrip(">") if "@" in sender else "account-update.net"
            raw = build_raw_eml(
                from_addr=sender,
                to_addr="employee@enterprise.org",
                subject=subj,
                body=body,
                date_dt=dt,
                spf_pass=False,
                dkim_pass=False,
                dmarc_pass=False,
                spf_domain=dom,
                dkim_domain=dom,
            )
            fname = f"human_phish_{idx}.eml"
            (DOCS_EML_DIR / fname).write_bytes(raw)
            tasks_to_run.append((fname, raw, dt, "HUMAN_PHISH"))

    total_count = len(tasks_to_run)
    print(f"\nTOTAL EMAILS TO PROCESS & PERSIST: {total_count}")
    print("Running parallel processing with bounded database sessions...\n")

    semaphore = asyncio.Semaphore(4)
    completed_stats = {"benign": 0, "suspicious": 0, "malicious": 0, "errors": 0}
    lock = asyncio.Lock()

    async def process_item(item_idx: int, filename: str, raw_bytes: bytes, target_dt: datetime, cat: str):
        async with semaphore:
            aid = str(uuid.uuid4())
            db = SessionLocal()
            try:
                # Execute full analysis pipeline
                analysis = await _execute_analysis_pipeline(raw_bytes, aid, db)

                # Set created_at to target_dt so SOC dashboard trends show realistic daily distributions
                db_record = db.query(AnalysisResult).filter(AnalysisResult.id == aid).first()
                if db_record:
                    db_record.created_at = target_dt
                    db.commit()

                v = analysis.verdict.lower() if analysis.verdict else "unknown"
                async with lock:
                    if v in completed_stats:
                        completed_stats[v] += 1
                    print(f"[{item_idx+1:03d}/{total_count}] {cat:<13} | {v.upper():<10} | Risk: {analysis.risk_score:02d} | Conf: {analysis.confidence:02d}% | {filename}")
            except Exception as exc:
                async with lock:
                    completed_stats["errors"] += 1
                    print(f"[{item_idx+1:03d}/{total_count}] ERROR on {filename}: {exc}")
            finally:
                db.close()

    tasks = [
        process_item(idx, item[0], item[1], item[2], item[3])
        for idx, item in enumerate(tasks_to_run)
    ]
    await asyncio.gather(*tasks)

    print("\n" + "=" * 75)
    print("PROCESSING COMPLETED! OUTCOME SUMMARY:")
    print("=" * 75)
    print(f"  Benign:     {completed_stats['benign']}")
    print(f"  Suspicious: {completed_stats['suspicious']}")
    print(f"  Malicious:  {completed_stats['malicious']}")
    print(f"  Errors:     {completed_stats['errors']}")

    # Check Supabase database storage size
    db = SessionLocal()
    try:
        res = db.execute(text('''
            SELECT table_name, 
                   pg_size_pretty(pg_total_relation_size(quote_ident(table_name))) as total_size,
                   pg_total_relation_size(quote_ident(table_name)) as size_bytes
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            ORDER BY size_bytes DESC;
        ''')).fetchall()
        print("\nSUPABASE DATABASE STORAGE AFTER POPULATION:")
        total_bytes = 0
        for r in res:
            print(f"  {r[0]:<30}: {r[1]} ({r[2]} bytes)")
            total_bytes += r[2] or 0
        mb_used = total_bytes / (1024 * 1024)
        pct_used = (mb_used / 500.0) * 100.0
        print(f"\nTotal DB Size: {mb_used:.2f} MB / 500.00 MB Free Tier Limit ({pct_used:.2f}% used, {500.0 - mb_used:.2f} MB available)")

        count_res = db.execute(text("SELECT COUNT(*) FROM analysis_results;")).scalar()
        print(f"Total analysis_results in database: {count_res}")
    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(main())
