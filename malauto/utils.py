import os
import math
import requests
from malauto.config import ALLOWED_EXTENSIONS
from malauto.config import CHAT_ID, BOT_TOKEN


def is_allow_file(filename):
    try:
        extension = os.path.splitext(filename)[-1].replace(".", "")
        return extension in ALLOWED_EXTENSIONS
    except Exception as ex:
        print(ex)
        return False


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)

    return "{0} {1}".format(s, size_name[i])


def malauto_send_telegram(text):
    try:
        token = BOT_TOKEN
        chat_id = CHAT_ID
        text = f"[MalAuto]:\n{text}"
        api_url = f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}&parse_mode=Markdown&text=`{text}`"
        _ = requests.get(api_url)
    except Exception as ex:
        print(ex)


def create_directory(path):
    try:
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
    except Exception as ex:
        print(ex)
