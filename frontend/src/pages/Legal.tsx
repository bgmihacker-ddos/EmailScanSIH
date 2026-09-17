import { ArrowLeft, ExternalLink, LockKeyhole, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';

type LegalSection = {
  title: string;
  paragraphs: string[];
};

const privacySections: LegalSection[] = [
  {
    title: 'What we collect',
    paragraphs: [
      'When you create an account or sign in with Google, we receive your name, email address, Google account identifier, and account verification status. We use this information to create and secure your operator account.',
      'If you connect Gmail, the application requests the Gmail read-only permission. We access only the messages you explicitly submit for analysis or the unread messages you choose to import. We do not send, edit, delete, or modify Gmail messages.',
    ],
  },
  {
    title: 'How we use information',
    paragraphs: [
      'Email content, headers, attachments, and extracted indicators are used to perform forensic analysis, authentication checks, threat-intelligence enrichment, reporting, and audit logging within the application.',
      'We do not sell personal information or use email content for advertising. Access is limited to authenticated users and authorized administrators who need it to operate or secure the service.',
    ],
  },
  {
    title: 'Storage and security',
    paragraphs: [
      'Authentication tokens are encrypted before storage. Analysis records and audit events are stored in the application database with access controls. Data is transmitted over HTTPS.',
      'No online service can guarantee absolute security. Please do not submit information that you are not authorized to process, including confidential data belonging to another person or organization.',
    ],
  },
  {
    title: 'Retention and your choices',
    paragraphs: [
      'Account and analysis data is retained while your account is active or as needed for security, compliance, and troubleshooting. You may request deletion of your account and associated data through the service operator.',
      'You can revoke Gmail access at any time from your Google Account security settings. Revoking access prevents future Gmail imports but does not automatically delete analysis records already created in the application.',
    ],
  },
];

const termsSections: LegalSection[] = [
  {
    title: 'Acceptable use',
    paragraphs: [
      'You may use Email Threat Detection only for legitimate defensive security, incident response, compliance, and authorized email analysis. You must have permission to process every message, mailbox, attachment, and account that you submit.',
      'You must not use the service to access another person\'s account, evade security controls, distribute malware, send unsolicited messages, or interfere with the application or its supporting infrastructure.',
    ],
  },
  {
    title: 'Google and Gmail access',
    paragraphs: [
      'Google sign-in is optional. If you connect Gmail, you authorize the application to read the Gmail data required for the analysis features you request. The application does not send, modify, or delete Gmail messages.',
      'You may disconnect Google access from your Google Account at any time. You are responsible for maintaining the security of your Google account and application credentials.',
    ],
  },
  {
    title: 'Analysis results',
    paragraphs: [
      'Threat scores, classifications, indicators, and recommendations are technical decision-support outputs. They may contain errors and must be reviewed by a qualified analyst before taking consequential action.',
      'You remain responsible for your decisions, legal obligations, data permissions, and response actions based on any result produced by the service.',
    ],
  },
  {
    title: 'Availability and changes',
    paragraphs: [
      'The service may be changed, suspended, or unavailable during maintenance or because of conditions outside the operator\'s control. We may update these terms when the service or applicable requirements change.',
      'Continued use after an updated effective date means you accept the revised terms. Questions or requests should be directed to the service operator through the support channel associated with your account.',
    ],
  },
];

function LegalPage({
  label,
  title,
  intro,
  sections,
}: {
  label: string;
  title: string;
  intro: string;
  sections: LegalSection[];
}) {
  return (
    <main className="min-h-screen px-5 py-6 text-ink-dim sm:px-8 lg:px-12">
      <div className="mx-auto max-w-4xl">
        <header className="flex flex-wrap items-center justify-between gap-4 border-b border-hairline-strong pb-5">
          <Link to="/login" className="inline-flex items-center gap-2 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-accent hover:brightness-125">
            <ArrowLeft size={15} /> Back to sign in
          </Link>
          <span className="inline-flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.14em] text-ink-mute"><ShieldCheck size={14} /> Email Threat Detection</span>
        </header>

        <section className="border-b border-hairline-strong py-14 sm:py-20">
          <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.24em] text-accent">{label}</p>
          <h1 className="mt-4 max-w-3xl text-4xl font-semibold tracking-[-0.04em] text-ink sm:text-6xl">{title}</h1>
          <p className="mt-6 max-w-2xl text-base leading-8 text-ink-dim">{intro}</p>
          <p className="mt-6 font-mono text-[10px] uppercase tracking-[0.16em] text-ink-mute">Effective date: September 13, 2026</p>
        </section>

        <div className="divide-y divide-hairline">
          {sections.map((section) => (
            <section key={section.title} className="grid gap-5 py-9 sm:grid-cols-[190px_1fr] sm:gap-10">
              <h2 className="text-lg font-semibold text-ink">{section.title}</h2>
              <div className="space-y-4 text-sm leading-7 text-ink-dim">
                {section.paragraphs.map((paragraph) => <p key={paragraph}>{paragraph}</p>)}
              </div>
            </section>
          ))}
        </div>

        <footer className="flex flex-wrap items-center justify-between gap-4 border-t border-hairline-strong py-8 text-xs text-ink-mute">
          <span className="inline-flex items-center gap-2"><LockKeyhole size={14} className="text-accent" /> Protected investigation surface</span>
          <Link to="/login" className="inline-flex items-center gap-2 text-accent hover:brightness-125">Open the application <ExternalLink size={13} /></Link>
        </footer>
      </div>
    </main>
  );
}

export function PrivacyPolicy() {
  return <LegalPage label="Privacy policy" title="Your data, handled for analysis." intro="This policy explains what Email Threat Detection collects, why it is used, and how Google sign-in and Gmail access work when you choose to connect them." sections={privacySections} />;
}

export function TermsOfService() {
  return <LegalPage label="Terms of service" title="Rules for responsible analysis." intro="These terms describe the permitted use of Email Threat Detection and the responsibilities that apply when you use its defensive email-analysis features." sections={termsSections} />;
}
