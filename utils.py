# utils.py

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ssl


class FlushFileHandler(logging.FileHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()


def setup_logging(logfile='ids.log'):
    handler = FlushFileHandler(logfile, mode='a')
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.addHandler(stream_handler)
    logger.setLevel(logging.INFO)


def send_email_alert(message):
    msg = MIMEMultipart('alternative')
    password = ""  # Put the automatic email password here!
    msg['From'] = ""  # Put the automatic email here!
    msg['To'] = ""  # PUT YOUR EMAIL HERE !
    msg['Subject'] = "Alert from IDS"

    text = message
    html = f"""
    <html>
    <body>
        <p style="font-size:16px;">Hello</p>
        <p style="font-size:16px;">{message}</p>
        <p style="font-size:16px;">Thank you King</p>
        <p style="font-size:16px;">Your IDS System</p>
    </body>
    </html>
    """
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    msg.attach(part1)
    msg.attach(part2)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        try:
            server.login(msg['From'], password)
            server.sendmail(msg['From'], msg['To'], msg.as_string())
        except Exception as e:
            log_error(str(e))


def log_info(message):
    logging.info(message)


def log_error(message):
    logging.error(message)
