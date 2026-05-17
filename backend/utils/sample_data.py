# Sample Phishing and Legitimate Email Datasets for Offline Triage and Local Simulation

# Example 1: Critical Risk - Microsoft Account SSO Impersonation
MICROSOFT_SPOOF_EML = b"""From: "Microsoft Security Office" <security@micr0soft-alert.com>
To: target_analyst@company.com
Reply-To: refund-desk@secure-billing-portal.net
Subject: [URGENT] Immediate Verification Required: Unusual Login Attempt
Date: Sun, 17 May 2026 14:22:00 +0530
Message-ID: <MS-99881-22919-ALERT@microsoft-alert.com>
Authentication-Results: mx.company.com; spf=fail; dkim=none; dmarc=fail
Received-SPF: fail (mx.company.com: domain of micr0soft-alert.com does not designate sender IP)

Dear Customer,

We detected an unusual sign-in attempt from an unrecognized IP address (185.220.101.44) trying to access your Microsoft 365 Outlook environment.

To protect your cloud environment, your account has been temporarily restricted.

You MUST confirm your identity and verify your account credentials within the next 24 hours, or your account will be permanently deactivated.

Please click the secure link below to verify your account details immediately:
https://micr0soft-alert.com/login/auth/sso/secure-portal-update.php?id=99281

If you did not make this request, please contact our support desk immediately.

Thank you,
The Microsoft Account Safety Team
"""

# Example 2: High Risk - Suspicious Billing Invoice with Macro-enabled attachment
INVOICE_MACRO_EML = b"""From: "Accounts Receivable - QuickBooks" <billing@quickbooks-invoicing.net>
To: analyst_demo@organization.org
Subject: Overdue Payment Notice: Invoice #INV-2026-9921
Date: Sat, 16 May 2026 10:15:22 +0530
Message-ID: <QB-INV-2026-9921@quickbooks-invoicing.net>
Authentication-Results: mx.company.com; spf=softfail; dkim=pass; dmarc=none

Dear Customer,

Please find attached the outstanding Invoice #INV-2026-9921 which is currently 14 days overdue.

A late fee of $150.00 will be added to your balance if payment is not completed via wire transfer by end-of-day.

Please review the attached spreadsheet Invoice_INV-2026-9921.docm to inspect the line items and confirm the billing information.

If you have any questions or require an extension, please contact billing immediately.

Best Regards,
QuickBooks Billing Services
"""

# Example 3: Critical Risk - PayPal Financial Phishing with URL Shorteners
PAYPAL_PHISHING_EML = b"""From: "PayPal Service Desk" <service@paypa1-security.com>
To: demo_user@target-corp.com
Subject: Notice of Account Restriction - Immediate Action Required
Date: Fri, 15 May 2026 09:12:00 +0530
Message-ID: <PP-ALERT-98218@paypa1-security.com>
Authentication-Results: mx.company.com; spf=fail; dkim=fail; dmarc=fail

Dear Customer,

Your PayPal account has been locked due to suspicious activity. We found multiple payment declines from an unfamiliar device.

To restore access, you must verify your identity immediately. Failure to verify within 48 hours will result in permanent suspension.

Please click the secure portal link below to update your credentials:
http://bit.ly/paypal-secure-portal-update-2026

Sincerely,
PayPal Security & Fraud Department
"""

# Example 4: Low Risk - Fully Legitimate Company Newsletter
NEWSLETTER_EML = b"""From: "GitHub Developer Services" <noreply@github.com>
To: employee@company.com
Subject: What's new in GitHub Enterprise: May 2026 Update
Date: Thu, 14 May 2026 18:30:00 +0530
Message-ID: <GH-NEWS-2026-MAY@github.com>
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass
Received-SPF: pass (mx.company.com: domain of github.com designates sender IP)

Hey Developers,

This month, we are excited to announce new advanced capabilities for GitHub Copilot, including improved context-aware suggestions and local repository indexing.

Check out the full changelog here:
https://github.com/blog/2026-05-whats-new-enterprise

We've also shipped security fixes and UI updates to Actions. Check out your dashboard for details!

Happy Coding,
The GitHub Team
"""

# Example 5: High Risk - Tax Refund Phishing with Redirects
TAX_REFUND_EML = b"""From: "Internal Revenue Service" <refunds@irs-online-gov.org>
To: citizen@gmail.com
Subject: Notification of Tax Refund: $1,420.50 Due to You
Date: Wed, 13 May 2026 11:05:00 +0530
Message-ID: <IRS-REFUND-992-TAX@irs-online-gov.org>
Authentication-Results: mx.company.com; spf=neutral; dkim=none; dmarc=fail

Taxpayer,

After the calculation of your annual fiscal activity for the tax year 2025, we have determined that you are eligible to receive a tax return refund of $1,420.50.

To claim your prize and complete your tax return submission online, click the link below:
https://irs-online-gov.org/claims/taxpayer-direct-deposit-portal.html

Note: Due to high volume, you must complete your refund request within 72 hours, or it will be canceled and the funds held.

Do not reply to this email, as this address is unmonitored.

IRS Online Portal Services
"""

SAMPLE_EMAILS = [
    {"raw": MICROSOFT_SPOOF_EML, "name": "Microsoft SSO Spoof Alert"},
    {"raw": INVOICE_MACRO_EML, "name": "Overdue QuickBooks Invoice"},
    {"raw": PAYPAL_PHISHING_EML, "name": "PayPal Restricted Alert"},
    {"raw": NEWSLETTER_EML, "name": "GitHub Newsletter"},
    {"raw": TAX_REFUND_EML, "name": "IRS Tax Refund Scam"}
]
