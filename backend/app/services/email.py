from abc import ABC, abstractmethod

class EmailProvider(ABC):
    @abstractmethod
    def send_email(self, to_email: str, subject: str, body: str):
        pass

class NullEmailProvider(EmailProvider):
    def send_email(self, to_email: str, subject: str, body: str):
        # Log instead of sending
        print(f"DEBUG: Would send email to {to_email}: {subject}")

def get_email_provider() -> EmailProvider:
    return NullEmailProvider()
