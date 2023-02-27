import os
import redis

from rq import Queue
from flask import Flask
from dotenv import load_dotenv
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_ALTERNATIVE = os.path.join(os.path.dirname(BASE_DIR), "upload")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)

username = os.getenv("MYSQL_USER")
password = os.getenv("MYSQL_USER_PASSWORD")
host = os.getenv("MYSQL_HOST")
dbname = os.getenv("MYSQL_DB_NAME")

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql://{username}:{password}@{host}/{dbname}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_DIR"] = os.getenv("UPLOAD_DIR") or UPLOAD_ALTERNATIVE
app.config["MAX_CONTENT_LENGTH"] = os.getenv("MAX_CONTENT_LENGTH")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ALLOWED_EXTENSIONS = set(os.getenv("ALLOWED_EXTENSIONS").split(","))

conn_report = redis.Redis()
conn_virustotal = redis.Redis()
queue_report = Queue(os.getenv("REPORT_QUEUE_NAME"), connection=conn_report)
queue_virustotal = Queue(os.getenv("VIRUSTOTAL_QUEUE_NAME"), connection=conn_virustotal)

SYS_INTERNAL_VT_URL = "https://www.virustotal.com/partners/sysinternals/file-reports"
SYS_INTERNAL_VT_API = os.getenv("SYS_INTERNAL_VT_API")

db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
