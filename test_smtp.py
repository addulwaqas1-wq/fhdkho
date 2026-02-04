import smtplib
import socket

def test_smtp_connection():
    mx_host = 'gmail-smtp-in.l.google.com'
    port = 25
    print(f"Testing connection to {mx_host}:{port}...")
    try:
        server = smtplib.SMTP(mx_host, port, timeout=5)
        server.ehlo()
        print("Success! Connected to Gmail SMTP.")
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to connect: {e}")
        return False

if __name__ == "__main__":
    test_smtp_connection()
