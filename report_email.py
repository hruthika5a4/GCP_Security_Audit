import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import os

def send_audit_email(project, excel_path, to_email):
    sender_email = "crtproject258@gmail.com"
    sender_app_password = "lxiz muyd zast abwg"

    html_output = f"<h2> GCP Security Audit Report for Project: {project}</h2>"

    msg = MIMEMultipart()
    msg["Subject"] = f"GCP Security Audit Report: {project}"
    msg["From"] = sender_email
    msg["To"] = to_email
    msg.attach(MIMEText(html_output, "html"))

    with open(excel_path, "rb") as f:
        part = MIMEApplication(f.read(), _subtype="xlsx")
        part.add_header("Content-Disposition", "attachment", filename=os.path.basename(excel_path))
        msg.attach(part)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_app_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        return "Email sent successfully."
    except Exception as e:
        return f"Failed to send email: {e}"
