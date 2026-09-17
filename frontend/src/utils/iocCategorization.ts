export type IocCategory = 'Actual IOC' | 'Infrastructure' | 'Forensic Artifact';

const INFRASTRUCTURE_DOMAINS = [
  'google.com', 'gmail.com', 'googlemail.com',
  'amazonses.com', 'aws.com',
  'sendgrid.net', 'sendgrid.com',
  'outlook.com', 'microsoft.com', 'office365.com', 'protection.outlook.com',
  'mimecast.com', 'pphosted.com', 'proofpoint.com',
  'mailgun.org', 'mailgun.net',
  'mandrillapp.com', 'mailchimp.com',
  'yahoo.com', 'hotmail.com'
];

export function categorizeIoc(ioc: any): IocCategory {
  const source = (ioc.source || '').toLowerCase();
  const value = (ioc.value || '').toLowerCase();
  const type = (ioc.type || '').toLowerCase();

  // 1. Forensic Artifacts
  if (
    source.includes('mailfrom') ||
    source.includes('header.from') ||
    source === 'from' ||
    source === 'to' ||
    source.includes('message_id') ||
    source.includes('message-id') ||
    source.includes('return-path') ||
    source.includes('reply-to') ||
    source.includes('authentication') ||
    source.includes('received') // sometimes hop IPs are caught as IOCs
  ) {
    // If it's a domain/URL in the body, it might be an actual IOC, but if source explicitly shows it's a header/parser artifact:
    return 'Forensic Artifact';
  }

  // 2. Infrastructure
  if (type === 'domain' || type === 'email' || type === 'url') {
    if (INFRASTRUCTURE_DOMAINS.some(domain => value.includes(domain))) {
      return 'Infrastructure';
    }
  }

  if (source.includes('mx') || source.includes('relay')) {
    return 'Infrastructure';
  }

  // 3. Actual IOCs
  return 'Actual IOC';
}
