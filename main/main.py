import json
import datetime
import time
import re
import keyring
import smtplib
from email.message import EmailMessage
from collections import Counter
from file_read_backwards import FileReadBackwards
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

class EventHandler(FileSystemEventHandler):
    alerted = 0
    last_modified_time = 0
    def on_any_event(self, event: FileSystemEvent) -> None:
        # Check if we have already alerted within the given email_interval (config)
        if (event.src_path == LOG_FILE) and (self.alerted == 1) and (time.time() > self.last_modified_time + EMAIL_INTERVAL):
            self.alerted = 0
        # Upon even trigger and not alerted, process the events and send the email
        if (event.src_path == LOG_FILE) and (self.alerted == 0):
            print("Hello")
            print("Goodbye")
            time.sleep(60)
            self.alerted = 1
            self.last_modified_time = time.time()
            log_array = process_events()
            # log_entries = List<LogEntry>
            log_entries = process_log_array(log_array)
            analytics = get_analytics(log_entries)
            if len(analytics["User-Agent"]) > 0 and len(analytics["Msg"]) > 0 and len(analytics["IP"]) > 0:
                send_email(analytics)
                print(f"Email sent! | {datetime.datetime.now()}")
            else:
                print(f"No logs to send. | {datetime.datetime.now()}")

class LogEntry:
    def __init__(self, user_agent, msg, ip):
        self.user_agent = user_agent
        self.msg = msg
        self.ip = ip
    def print_info(self):
        print(f"User Agent: {self.user_agent}, Msg: {self.msg}, IP: {self.ip}")

class Packet:
    def __init__(self, event_id, user_agent):
        self.event_id = event_id
        self.user_agent = user_agent

class Event:
    def __init__(self, event_id, msg, ip):
        self.event_id = event_id
        self.msg = msg
        self.ip = ip

print("Hi")

with open('..\\config\\config.json') as file:
    CONFIG = json.load(file)
LOG_FILE = CONFIG["log_file"]
LOG_FOLDER = CONFIG["log_folder"]
EMAIL_INTERVAL = CONFIG["email_interval"]
EMAIL_SERVICE = CONFIG["email_service"]
EMAIL_FROM = CONFIG["email_from"]
EMAIL_TO = CONFIG["email_to"]
SMTP_SERVER = CONFIG["smtp_server"]
SMTP_PORT = CONFIG["smtp_port"]

def send_email(analytics):
    msg =  EmailMessage()
    msg["Subject"] = f"ALERT: {analytics["Count"]} packets received | IP: {analytics["IP"][0][0]}"
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg.set_content(f"""
Statistics over last 60 seconds:
    
Packets Sent: {analytics["Count"]}
    
Top 3 Alerts:
    {'\n'.ljust(5).join(f'{stat[0]} | {stat[1]}' for stat in analytics["Msg"])}
    
Top 3 IPs:
    {'\n'.ljust(5).join(f'{stat[0]} | {stat[1]}' for stat in analytics["IP"])}

Top 3 User-Agents:
    {'\n'.ljust(5).join(f'{stat[0]} | {stat[1]}' for stat in analytics["User-Agent"])}
""")
    email_password = keyring.get_password(EMAIL_SERVICE,EMAIL_FROM)
    if email_password == None:
        print("Email credentials not setup properly. If this is a surpise, check credential manager.")
        return
    try:
        server_sll = smtplib.SMTP_SSL(SMTP_SERVER,SMTP_PORT)
        server_sll.login(EMAIL_FROM,email_password)
        server_sll.send_message(msg)
        server_sll.close()
    except:
        print(f"Failed to send email | {datetime.datetime.now()}")

def send_report(analytics):
    msg =  EmailMessage()
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    if len(analytics["User-Agent"]) > 0 and len(analytics["Msg"]) > 0 and len(analytics["IP"]) > 0:
        msg["Subject"] = f"!!! DAILY REPORT - {datetime.date.today() - datetime.timedelta(days=1)} (ACTIVITY DETECTED): {analytics["Count"]} packets received."
        msg.set_content(f"""
Statistics for {datetime.date.today() - datetime.timedelta(days=1)}
    
Packets Sent: {analytics["Count"]}
    
Top 3 Alerts:
    {'\n'.ljust(5).join(f'{stat[0]} | {stat[1]}' for stat in analytics["Msg"])}
    
Top 3 IPs:
    {'\n'.ljust(5).join(f'{stat[0]} | {stat[1]}' for stat in analytics["IP"])}

Top 3 User-Agents:
    {'\n'.ljust(5).join(f'{stat[0]} | {stat[1]}' for stat in analytics["User-Agent"])}
"""
        )
        print(f"Report sent! | {datetime.datetime.now()}")
    
    elif len(analytics["User-Agent"]) == 0 and len(analytics["Msg"]) == 0 and len(analytics["IP"]) == 0:
        msg["Subject"] = f"DAILY REPORT - {datetime.date.today() - datetime.timedelta(days=1)}: Just checking in :) - {analytics["Count"]} packets received."
        msg.set_content(f"""
Statistics for {datetime.date.today() - datetime.timedelta(days=1)}

Nothing to report.
"""
        )
        print(f"Nothing to report. | {datetime.datetime.now()}")
    
    else:
        print(f"Something unexpected happened. | {datetime.datetime.now()}")

    email_password = keyring.get_password(EMAIL_SERVICE,EMAIL_FROM)
    if email_password == None:
        print("Email credentials not setup properly. If this is a surpise, check credential manager.")
        return
    try:
        server_sll = smtplib.SMTP_SSL(SMTP_SERVER,SMTP_PORT)
        server_sll.login(EMAIL_FROM,email_password)
        server_sll.send_message(msg)
        server_sll.close()
    except:
        print("Failed to send email")

def get_daily_stats():
    log_array = process_events_day()
    log_entries = process_log_array(log_array)
    analytics = get_analytics(log_entries)
    return analytics

def get_previous_midnight():
    previous_day = datetime.datetime.today() - datetime.timedelta(days=1)
    previous_midnight_datetime = datetime.datetime.combine(previous_day,datetime.time.min)
    return previous_midnight_datetime.timestamp()

def get_last60():
    current_timestamp = time.time()
    sixty_ago_timestamp = current_timestamp - 60
    return sixty_ago_timestamp

def is_event_yesterday(log):
    log_type = log["type"]
    if log_type == "packet":
        timestamp = log["packet"]["event-second"]
    elif log_type == "event":
        timestamp = log["event"]["event-second"]
    else:
        timestamp = None

    midnight = get_previous_midnight()

    if (timestamp != None) and (timestamp >= midnight):
        return True
    else:
        return False
    
def is_event_last60(log):
    log_type = log["type"]
    if log_type == "packet":
        timestamp = log["packet"]["event-second"]
    elif log_type == "event":
        timestamp = log["event"]["event-second"]
    else:
        timestamp = None

    last60 = get_last60()

    if (timestamp != None) and (timestamp >= last60):
        return True
    else:
        return False    

def get_analytics(log_entries):
    analytics = {}
    log_count = len(log_entries)
    user_agent_count = Counter(log_entry.user_agent for log_entry in log_entries).most_common(3)
    msg_count = Counter(log_entry.msg for log_entry in log_entries).most_common(3)
    ip_count = Counter(log_entry.ip for log_entry in log_entries).most_common(3)
    analytics.update({"Count":log_count,"User-Agent":user_agent_count,"Msg":msg_count,"IP":ip_count})
    return analytics

# Use event-id
def process_log_array(log_array):
    packet_dict = {}
    event_dict = {}
    log_entries = []
    for log in log_array:
        log_type = log["type"]
        if log_type == "packet":
            event_id = log["packet"]["event-id"]
            data_printable = log["packet"]["data-printable"]
            user_agent = re.search(r'(?<=User-Agent:\s).*?(?=\r\n)',data_printable)
            if user_agent:
                user_agent = user_agent.group()
            packet = Packet(event_id, user_agent)
            packet_dict.update({packet.event_id:packet})
        elif log_type == "event":
            event_id = log["event"]["event-id"]
            msg = log["event"]["msg"]
            ip = log["event"]["source-ip"]
            event = Event(event_id, msg, ip)
            event_dict.update({event.event_id:event})
        else:
            continue
    for key in packet_dict:
        if key in event_dict:
            user_agent = packet_dict[key].user_agent
            msg = event_dict[key].msg
            ip = event_dict[key].ip
            log_entries.append(LogEntry(user_agent,msg,ip))
        else:
            continue
    return log_entries

# Potentially need error handling in case non-json is passed into is_event_today
def process_events():
    with FileReadBackwards(LOG_FILE, encoding="UTF-8") as log_file:
        logs = []
        for line in log_file:
            log = json.loads(line)
            if is_event_last60(log):
                logs.append(log)
            else:
                return logs
        return logs

def process_events_day():
    with FileReadBackwards(LOG_FILE, encoding="UTF-8") as log_file:
        logs = []
        for line in log_file:
            log = json.loads(line)
            if is_event_yesterday(log):
                logs.append(log)
            else:
                return logs
        return logs
                

event_handler = EventHandler()
observer = Observer()
observer.schedule(event_handler, LOG_FOLDER, recursive=True)
observer.start()
today = datetime.date.today()
try:
    while True:
        if datetime.date.today() > today:
            analytics = get_daily_stats()
            send_report(analytics)
            today = datetime.date.today()
        time.sleep(1)
except KeyboardInterrupt:
    print("Shutting down.")
finally:
    observer.stop()
    observer.join()

