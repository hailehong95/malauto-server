import os
import re
import json
import time
import random
import string
import zipfile
import requests
import dateutil.parser
from dotenv import load_dotenv
from datetime import datetime, timedelta

from rq.decorators import job
from malauto.config import app
from malauto.config import SYS_INTERNAL_VT_URL, SYS_INTERNAL_VT_API
from malauto.models import Employee, Campaign, Autoruns, Addons, Files
from malauto.config import db, conn_report, conn_virustotal, queue_virustotal
from malauto.models import Info, Networking, Process, EventLogs, LastActivity, Virustotal

load_dotenv()

MY_PARAMS = {'apikey': str(SYS_INTERNAL_VT_API)}
MY_HEADERS = {'User-Agent': 'VirusTotal', 'Content-type': 'application/json'}
BATCH_SIZE = 100

REPORT_NAME = {
    'mac': 'mac.json',
    'net': 'net.json',
    'info': 'info.json',
    'proc': 'proc.json',
    'files': 'files.json',
    'pslogs': 'pslogs.json',
    'addons': 'addons.json',
    'autorun': 'autorun.json',
    'lastactivity': 'lastactivity.json'
}

PROCESS_VERIFIED = {
    0: 'Valid',
    2: 'NotSigned',
    3: 'HashMismatch'
}

# Ref: https://sysnetdevops.com/2017/04/24/exploring-the-powershell-alternative-to-netstat/
NETWORK_STATE = {
    1: 'CLOSED',
    2: 'LISTENING',
    3: 'SYN SENT',
    4: 'SYN RECEIVED',
    5: 'ESTABLISHED',
    6: 'FINSIHED 1',
    7: 'FINISHED 2',
    8: 'CLOSE WAIT',
    9: 'CLOSING',
    10: 'LAST ACKNOWLEDGE',
    11: 'TIME WAIT',
    12: 'DELETE TCB',
    100: 'BOUND'
}


def get_random_number(start, end):
    return random.randint(start, end)


def get_random_string(length):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for i in range(length))


def get_random_date(start, end):
    delta = end - start
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = random.randrange(int_delta)
    return start + timedelta(seconds=random_second)


# Ref: https://www.geeksforgeeks.org/find-all-the-numbers-in-a-string-using-regular-expression-in-python/
def extract_timecreated(bad_str):
    return re.findall(r'[0-9]+', bad_str)[0]


# Ref: https://stackoverflow.com/questions/24522793/how-can-i-add-n-milliseconds-to-a-datetime-in-python
# https://social.technet.microsoft.com/Forums/ie/en-US/720aaf07-9da1-4f29-bd8a-718c198b7cb3/converting-datetime-values-from-json-file?forum=winserverpowershell
def get_correct_timecreated(delta):
    start_date = datetime(1970, 1, 1)
    return start_date + timedelta(milliseconds=int(delta))


def get_hostapplication_ps(message):
    for x in message.split('\r\n\t'):
        if x.startswith('HostApplication'):
            return x.replace('HostApplication=', '')
    return ''


def load_json(file_path):
    try:
        buff = {}
        with open(file_path, encoding='utf-8-sig') as f:
            buff = json.load(f)
    except Exception as ex:
        print(ex)
    return buff


def unzip_file(source_file, dest_folder):
    try:
        with zipfile.ZipFile(source_file, 'r') as zip_ref:
            zip_ref.extractall(dest_folder)
    except Exception as ex:
        print(ex)


# Query vào db lấy ra campaign hiện tại theo thời gian truyền vào
def get_current_campaign(today):
    try:
        item_campaign = db.session.query(Campaign).all()
        for it in item_campaign:
            if it.start_date <= today <= it.end_date:
                return it.campaign_id
    except Exception as ex:
        print(ex)
    return None


# Query vào bảng Virustotal lấy ra kết quả VT Detection. Ex: 0/68
def get_vt_detection_ratio(sha1_hash):
    try:
        vt_item = db.session.query(Virustotal).filter_by(sha1_hash=sha1_hash).first()
        if vt_item:
            return vt_item.detection_ratio
    except Exception as ex:
        print(ex)
    return 'updating'


# Cập nhập những bản ghi chưa có kết quả VT vào bảng Virustotal
def update_vt_detection_ratio(sha1_hash, detection_ratio):
    try:
        vt_item = db.session.query(Virustotal).filter_by(sha1_hash=sha1_hash, detection_ratio='updating').first()
        if vt_item:
            vt_item.detection_ratio = detection_ratio
            db.session.commit()
    except Exception as ex:
        db.session.rollback()
        print(ex)


# Cập nhập kết quả VT Detection vào bảng Autoruns, Process, Files
# Trong các bảng có thể có nhiểu bản ghi có cùng hash file.
# Chỉ cập nhật những bản ghi chưa có kết quả VT Detection
# Tham khảo: https://stackoverflow.com/a/38294885
def update_detection_ratio_autoruns(employee_id, campaign_id, sha1_hash, detection_ratio):
    try:
        list_autorun_items = db.session.query(Autoruns).filter_by(employee_id=employee_id, campaign_id=campaign_id, sha1_hash=sha1_hash, virustotal='updating').all()
        if list_autorun_items:
            for item in list_autorun_items:
                item.virustotal = detection_ratio
            db.session.commit()
    except Exception as ex:
        db.session.rollback()
        print(ex)


def update_detection_ratio_process(employee_id, campaign_id, sha1_hash, detection_ratio):
    try:
        list_process_items = db.session.query(Process).filter_by(employee_id=employee_id, campaign_id=campaign_id, sha1_hash=sha1_hash, virustotal='updating').all()
        if list_process_items:
            for item in list_process_items:
                item.virustotal = detection_ratio
            db.session.commit()
    except Exception as ex:
        db.session.rollback()
        print(ex)


def update_detection_ratio_files(employee_id, campaign_id, sha1_hash, detection_ratio):
    try:
        list_file_items = db.session.query(Files).filter_by(employee_id=employee_id, campaign_id=campaign_id, sha1_hash=sha1_hash, virustotal='updating').all()
        if list_file_items:
            for item in list_file_items:
                item.virustotal = detection_ratio
            db.session.commit()
    except Exception as ex:
        db.session.rollback()
        print(ex)


# Thêm bản ghi (hash) mới vào bảng Virustotal
# Mặc định khi thêm hash vào db: detection_ratio = 'updating'
# Khi gọi hàm này cần kiểm tra hash đã tồn tại trong db chưa.
def insert_hash_to_database(md5_hash, sha1_hash, sha256_hash, detection_ratio):
    try:
        vt_item = Virustotal(md5_hash, sha1_hash, sha256_hash, detection_ratio)
        db.session.add(vt_item)
        db.session.commit()
    except Exception as ex:
        db.session.rollback()
        print(ex)


# Xử lý info.json
def systeminfo_process(employee_id, campaign_id, info_json_file, mac_json_file):
    num_of_item = 0
    try:
        sysinfo_data = load_json(info_json_file)
        mac_data = load_json(mac_json_file)
        host_name = sysinfo_data['Host Name']
        os_name = sysinfo_data['OS Name']
        os_version = sysinfo_data['OS Version']
        registered_owner = sysinfo_data['Registered Owner']
        original_install_date = dateutil.parser.parse(sysinfo_data['Original Install Date'])
        system_manufacturer = sysinfo_data['System Manufacturer']
        system_type = sysinfo_data['System Type']
        processor = sysinfo_data['Processor(s)'].replace(',[', '</br>[')
        total_physical_memory = sysinfo_data['Total Physical Memory']
        domain = sysinfo_data['Domain']
        hotfix = sysinfo_data['Hotfix(s)'].replace(',[', '</br>[')
        network_card = sysinfo_data['Network Card(s)'].replace(',[', '</br>[')

        # Fix trường hợp máy chỉ có duy nhất 1 địa chỉ mac (máy đó không cài phần mềm máy ảo)
        # Lúc này type(mac_data) = dict dẫn đến parsing bị lỗi
        # Solution: type(mac_data) = list
        if type(mac_data) is dict:
            temp = list()
            temp.append(mac_data)
            mac_data = temp
        macaddress = ''
        for it in mac_data:
            macaddress += f"{it['MacAddress']} ({it['Name']}), "
        item = db.session.query(Info).filter_by(employee_id=employee_id, campaign_id=campaign_id).first()
        if not item:
            new_item = Info(employee_id, campaign_id, host_name, os_name, os_version, registered_owner, original_install_date, system_manufacturer, system_type, processor, total_physical_memory, domain, hotfix, network_card, macaddress[:-2].replace(', ', '</br>'))
            db.session.add(new_item)
            db.session.commit()
            num_of_item += 1
    except Exception as ex:
        db.session.rollback()
        print(ex)
    return num_of_item


# check None or ""
def is_valid_record(*args):
    for x in args:
        if x is None or len(x) == 0:
            return False
    return True


# Xử lý autorun.json
def autoruns_process(employee_id, campaign_id, autorun_json_file):
    autorun_data = load_json(autorun_json_file)
    icount = 0
    for it in autorun_data:
        # item đọc từ json file nếu không hợp lệ sẽ được bỏ qua
        if len(it['Time']) == 0:
            continue
        time = dateutil.parser.parse(it['Time'])
        entry_location = it['Entry Location']
        enabled = it['Enabled']
        category = it['Category']
        signer = it['Signer']
        company = it['Company']
        image_path = it['Image Path']
        launch_string = it['Launch String']
        md5_hash = it['MD5']
        sha1_hash = it['SHA-1']
        sha256_hash = it['SHA-256']
        # local check
        virustotal = get_vt_detection_ratio(sha1_hash)
        if is_valid_record(entry_location, enabled, category, signer, company, image_path, launch_string, md5_hash, sha1_hash, sha256_hash):
            try:
                # kiểm tra hash tồn tại
                icheck = db.session.query(Virustotal).filter_by(sha1_hash=sha1_hash).first()
                if not icheck:
                    # nếu chưa tồn tại thì thêm vào bảng virustoal
                    insert_hash_to_database(md5_hash, sha1_hash, sha256_hash, 'updating')
                # cập nhật bản ghi vào bảng Autoruns
                autorun_item = Autoruns(employee_id, campaign_id, time, entry_location, enabled, category, signer, company, image_path, launch_string, md5_hash, sha1_hash, sha256_hash, virustotal)
                db.session.add(autorun_item)
                db.session.commit()
                icount += 1
            except Exception as ex:
                db.session.rollback()
                print(ex)
    return f"{icount}/{len(autorun_data)}"


# Xử lý files.json
def files_process(employee_id, campaign_id, sigcheck_json_file):
    sigcheck_data = load_json(sigcheck_json_file)
    icount = 0
    for it in sigcheck_data:
        # bỏ qua item không hợp lệ
        if it['MD5'] is None:
            continue
        path = it['Path']
        verified = it['Verified']
        time = dateutil.parser.parse(it['Date'])
        publisher = it['Publisher']
        product_version = it['Product Version']
        entropy = it['Entropy']
        md5_hash = it['MD5']
        sha1_hash = it['SHA1']
        sha256_hash = it['SHA256']
        # local check
        virustotal = get_vt_detection_ratio(sha1_hash)
        try:
            # kiểm tra hash tồn tại
            icheck = db.session.query(Virustotal).filter_by(sha1_hash=sha1_hash).first()
            if not icheck:
                insert_hash_to_database(md5_hash, sha1_hash, sha256_hash, 'updating')
            file_item = Files(employee_id, campaign_id, path, verified, time, publisher, product_version, entropy, md5_hash, sha1_hash, sha256_hash, virustotal)
            db.session.add(file_item)
            db.session.commit()
            icount += 1
        except Exception as ex:
            db.session.rollback()
            print(ex)
    return f"{icount}/{len(sigcheck_data)}"


# Xử lý proc.json
def proc_process(employee_id, campaign_id, proc_json_file):
    process_data = load_json(proc_json_file)
    icount = 0
    for it in process_data:
        # bỏ qua nếu item không hợp lệ
        if it['Path'] is None or it['MD5'] is None:
            continue
        pid = it['Id']
        process_name = it['ProcessName']
        username = it['UserName']
        description = it['Description']
        company = it['Company']
        verified = PROCESS_VERIFIED.get(it['Verified'], 'Unknown')
        md5_hash = it['MD5']
        sha1_hash = it['SHA-1']
        sha256_hash = it['SHA-256']
        command_line = it['CommandLine']
        path = it['Path']
        # local check
        virustotal = get_vt_detection_ratio(sha1_hash)
        try:
            # kiểm tra hash tồn tại
            icheck = db.session.query(Virustotal).filter_by(sha1_hash=sha1_hash).first()
            if not icheck:
                insert_hash_to_database(md5_hash, sha1_hash, sha256_hash, 'updating')
            proc_item = Process(employee_id, campaign_id, pid, process_name, username, description, company, verified, md5_hash, sha1_hash, sha256_hash, command_line, path, virustotal)
            db.session.add(proc_item)
            db.session.commit()
            icount += 1
        except Exception as ex:
            db.session.rollback()
            print(ex)
    return f"{icount}/{len(process_data)}"


# Xử lý net.json
def network_process(employee_id, campaign_id, net_json_file):
    network_data = load_json(net_json_file)
    icount = 0
    for it in network_data:
        process_name = it['ProcessName']
        pid = it['PID']
        local_address = it['LocalAddress']
        local_port = it['LocalPort']
        remote_address = it['RemoteAddress']
        remote_port = it['RemotePort']
        state = NETWORK_STATE.get(it['State'], 'UNKNOWN')
        try:
            net_item = Networking(employee_id, campaign_id, process_name, pid, local_address, local_port, remote_address, remote_port, state)
            db.session.add(net_item)
            db.session.commit()
            icount += 1
        except Exception as ex:
            db.session.rollback()
            print(ex)
    return f"{icount}/{len(network_data)}"


# Xử lý pslogs.json
def eventlogs_process(employee_id, campaign_id, eventlogs_json_file):
    eventlogs_data = load_json(eventlogs_json_file)
    icount = 0
    for it in eventlogs_data:
        event_id = it['Id']
        time_created = get_correct_timecreated(extract_timecreated(it['TimeCreated']))
        log_name = it['LogName']
        process_id = it['ProcessId']
        level_display_name = it['LevelDisplayName']
        message = get_hostapplication_ps(it['Message'])
        try:
            event_item = EventLogs(employee_id, campaign_id, event_id, time_created, log_name, process_id, level_display_name, message)
            db.session.add(event_item)
            db.session.commit()
            icount += 1
        except Exception as ex:
            db.session.rollback()
            print(ex)
    return f"{icount}/{len(eventlogs_data)}"


# Xử lý lastactivity.json
def lastactivity_process(employee_id, campaign_id, lastactivity_json_file):
    lastactivity_data = load_json(lastactivity_json_file)
    icount = 0
    for it in lastactivity_data:
        action_time = dateutil.parser.parse(it['Action Time'])
        description = it['Description']
        filename = it['Filename']
        full_path = it['Full Path']
        more_information = it['More Information']
        file_extension = it['File Extension']
        data_source = it['Data Source']
        if data_source is None:
            data_source = 'null'
        try:
            lastactivity_item = LastActivity(employee_id, campaign_id, action_time, description, filename, full_path, more_information, file_extension, data_source)
            db.session.add(lastactivity_item)
            db.session.commit()
            icount += 1
        except Exception as ex:
            db.session.rollback()
            print(ex)
    return f"{icount}/{len(lastactivity_data)}"


# Xử lý addons.json
def browseraddon_process(employee_id, campaign_id, addon_json_file):
    addon_data = load_json(addon_json_file)
    icount = 0
    for it in addon_data:
        # zero or 'None'
        if len(str(it['Status'])) == 0 or len(str(it['Status'])) == 4:
            continue
        item_id = it['Item ID']
        status = it['Status']
        web_browser = it['Web Browser']
        addon_type = it['Addon Type']
        name = it['Name']
        version = it['Version']
        title = it['Title']
        # zero or 'None', fix default datetime
        if len(str(it['Install Time'])) == 0 or len(str(it['Install Time'])) == 4:
            install_time = datetime(2000, 1, 1)
        else:
            install_time = dateutil.parser.parse(it['Install Time'])
        addon_filename = it['Addon Filename']
        try:
            addon_item = Addons(employee_id, campaign_id, item_id, status, web_browser, addon_type, name, version, title, install_time, addon_filename)
            db.session.add(addon_item)
            db.session.commit()
            icount += 1
        except Exception as ex:
            db.session.rollback()
            print(ex)
    return f"{icount}/{len(addon_data)}"


# query to virustotal, maximum 100 hash and return json object
def search_on_virustotal(batch_hash):
    list_data = []
    for sha1_item in batch_hash:
        str1 = get_random_string(get_random_number(5, 10))
        str2 = get_random_string(get_random_number(5, 10))
        str3 = get_random_string(get_random_number(5, 10))
        file_path = f"C:\\{str1}\\{str2}\\{str3}.exe"
        dr1 = datetime.strptime('2000/1/1 1:10 AM', '%Y/%m/%d %I:%M %p')
        dr2 = datetime.strptime('2020/12/1 11:11 PM', '%Y/%m/%d %I:%M %p')
        date_random = get_random_date(dr1, dr2)
        item = {
            'autostart_location': '',
            'autostart_entry': '',
            'hash': sha1_item,
            'image_path': file_path,
            'creation_datetime': str(date_random)
        }
        list_data.append(item)
    try:
        response = requests.post(SYS_INTERNAL_VT_URL, params=MY_PARAMS, headers=MY_HEADERS, json=list_data)
        time.sleep(3)
        if response.status_code == 200:
            return response.json()
    except Exception as ex:
        print(ex)
    return None


# background task for virustotal worker
@job('virustotal', connection=conn_virustotal, timeout=3600)
def virustotal_background_task(hash_db, employee_id, campaign_id):
    icount = 0
    start_time = time.time()
    print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Virustotal task is running, Total {len(hash_db)} hash")
    try:
        for i in range(0, len(hash_db), BATCH_SIZE):
            # Step 1: Chia nhỏ thành các batch, mỗi batch tối đa 100 hash
            batch_hash = hash_db[i:i + BATCH_SIZE]
            print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Querying {len(batch_hash)} hash")
            json_batch = search_on_virustotal(batch_hash)
            # Step 2: cập nhật kết quả VT vào bảng Virustotal
            if json_batch is not None:
                print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Updating VT detection ratio to DB")
                for item in json_batch['data']:
                    if item['found'] is True:
                        update_vt_detection_ratio(item['hash'], item['detection_ratio'])
                        update_detection_ratio_autoruns(employee_id, campaign_id, item['hash'], item['detection_ratio'])
                        update_detection_ratio_process(employee_id, campaign_id, item['hash'], item['detection_ratio'])
                        update_detection_ratio_files(employee_id, campaign_id, item['hash'], item['detection_ratio'])
                        icount += 1
            else:
                print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] VT Result is None")
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Total {icount}/{len(hash_db)} new hash updated")
    except Exception as ex:
        print(ex)
    finally:
        end_time = time.time()
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Virustotal Task complete! Time taken: {timedelta(seconds=end_time - start_time)}")
    return len(hash_db)


# background task for report worker
# Ref 1: https://python-rq.org/docs/#the-job-decorator
# Ref 3: https://python-rq.org/docs/#enqueueing-jobs
@job('report', connection=conn_report, timeout=900)
def report_background_task(filename):
    print(f"{datetime.now().strftime('%H:%M:%S')} [ {get_current_campaign(datetime.today())} | {filename.split('_')[0]} ] Report task is running!")
    start_time = time.time()
    try:
        employee_id = filename.split('_')[0]
        campaign_id = get_current_campaign(datetime.today())
        if campaign_id is None:
            return "Campaign ID is None. Report Task ending!"
        source_file = app.config["UPLOAD_DIR"] + filename
        dest_folder = app.config["UPLOAD_DIR"] + filename.replace('.zip', '') + '/'

        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 1/12 : Extract report: {filename}")
        unzip_file(source_file, dest_folder)

        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 2/12 : User information processing")
        num_of_employee = systeminfo_process(employee_id, campaign_id, dest_folder + REPORT_NAME['info'], dest_folder + REPORT_NAME['mac'])
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] DONE! Total: {num_of_employee} employee added")

        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 3/12 : Autoruns processing")
        num_of_autorun = autoruns_process(employee_id, campaign_id, dest_folder + REPORT_NAME['autorun'])
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] DONE! Total: {num_of_autorun} valid records")

        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 4/12 : Files processing")
        num_of_file = files_process(employee_id, campaign_id, dest_folder + REPORT_NAME['files'])
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] DONE! Total: {num_of_file} valid records")

        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 5/12 : Process processing")
        num_of_proc = proc_process(employee_id, campaign_id, dest_folder + REPORT_NAME['proc'])
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] DONE! Total: {num_of_proc} valid records")

        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 6/12 : Network processing")
        num_of_net = network_process(employee_id, campaign_id, dest_folder + REPORT_NAME['net'])
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] DONE! Total: {num_of_net} valid records")

        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 7/12 : Event Logs processing")
        num_of_event = eventlogs_process(employee_id, campaign_id, dest_folder + REPORT_NAME['pslogs'])
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] DONE! Total: {num_of_event} valid records")

        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 8/12 : Last Activity processing")
        num_of_activity = lastactivity_process(employee_id, campaign_id, dest_folder + REPORT_NAME['lastactivity'])
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] DONE! Total: {num_of_activity} valid records")

        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 9/12 : Browser Addon processing")
        num_of_addon = browseraddon_process(employee_id, campaign_id, dest_folder + REPORT_NAME['addons'])
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] DONE! Total: {num_of_addon} valid records")

        # Cập nhập trạng thái xử lý report từ 'processing' thành 'successful'
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 10/12 : Update status of user report")
        employee_item = db.session.query(Employee).filter_by(employee_id=employee_id, campaign_id=campaign_id, status='processing').first()
        if employee_item:
            employee_item.status = 'successful'
            employee_item.datetime = datetime.now()
            db.session.commit()
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] DONE! Updated status report: successful")

        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 11/12 : Get hash from Virustotal Table")
        # Sau khi xử lý dữ liệu xong và thêm vào các bảng. Lấy ra tất cả các sha1 hash trong bảng Virustotal
        hash_db = []
        virustotal_all_item = db.session.query(Virustotal).filter_by(detection_ratio='updating').all()
        if virustotal_all_item:
            for item in virustotal_all_item:
                hash_db.append(item.sha1_hash)
        # Tiến hành thêm task cho virustotal worker query lên VT số lượng lớn hash
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Step 12/12 : Push task for Virustotal Worker")
        job = queue_virustotal.enqueue(virustotal_background_task, hash_db, employee_id, campaign_id, job_timeout='60m')
    except Exception as ex:
        db.session.rollback()
        print(ex)
    finally:
        end_time = time.time()
        print(f"{datetime.now().strftime('%H:%M:%S')} [ {campaign_id} | {employee_id} ] Report Task complete! Time taken: {timedelta(seconds=end_time - start_time)}")
    return 'You are God!'
