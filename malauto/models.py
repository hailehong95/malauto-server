from malauto.config import db
from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash


class Employee(db.Model):
    __tablename__ = 'employee_info'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(10), nullable=False)
    campaign_id = db.Column(db.String(10), nullable=False)
    full_name = db.Column(db.String(100))
    status = db.Column(db.String(15))
    report_name = db.Column(db.String(100))
    datetime = db.Column(db.DateTime, nullable=False, default=datetime.now())
    report_size = db.Column(db.String(20))
    group_name = db.Column(db.String(50))
    platform = db.Column(db.String(50))
    result = db.Column(db.String(50), default='unknown')
    verified = db.Column(db.String(100), default='unknown')

    def __init__(self, employee_id, campaign_id, full_name, status, report_name, report_size, group_name, platform):
        self.employee_id = employee_id
        self.campaign_id = campaign_id
        self.full_name = full_name
        self.status = status
        self.report_name = report_name
        self.datetime = datetime.now()
        self.report_size = report_size
        self.group_name = group_name
        self.platform = platform

    def __repr__(self):
        return '<Employee {}>'.format(self.full_name)


class Campaign(db.Model):
    __tablename__ = 'campaign_info'
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.String(10), nullable=False)
    campaign_name = db.Column(db.String(255))
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)

    def __init__(self, campaign_id, campaign_name, start_date, end_date):
        self.campaign_id = campaign_id
        self.campaign_name = campaign_name
        self.start_date = start_date
        self.end_date = end_date

    def __repr__(self):
        return '<Campaign {}>'.format(self.campaign_name)


class Autoruns(db.Model):
    __tablename__ = 'rp_autoruns'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(10), nullable=False)
    campaign_id = db.Column(db.String(10), nullable=False)
    time = db.Column(db.DateTime, default=datetime.now())
    entry_location = db.Column(db.String(4096))  # 65535
    enabled = db.Column(db.String(20))
    category = db.Column(db.String(50))
    signer = db.Column(db.String(255))
    company = db.Column(db.String(255))
    image_path = db.Column(db.String(1024))  # 65535
    launch_string = db.Column(db.String(4096))  # 65535
    md5_hash = db.Column(db.String(65))
    sha1_hash = db.Column(db.String(65))
    sha256_hash = db.Column(db.String(65))
    virustotal = db.Column(db.String(10), default='updating')

    def __init__(self, employee_id, campaign_id, time, entry_location, enabled, category, signer, company, image_path,
                 launch_string, md5_hash, sha1_hash, sha256_hash, virustotal):
        self.employee_id = employee_id
        self.campaign_id = campaign_id
        self.time = time
        self.entry_location = entry_location
        self.enabled = enabled
        self.category = category
        self.signer = signer
        self.company = company
        self.image_path = image_path
        self.launch_string = launch_string
        self.md5_hash = md5_hash
        self.sha1_hash = sha1_hash
        self.sha256_hash = sha256_hash
        self.virustotal = virustotal

    def __repr__(self):
        return '<Autoruns {}>'.format(self.id)


class Addons(db.Model):
    __tablename__ = 'rp_addons'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(10), nullable=False)
    campaign_id = db.Column(db.String(10), nullable=False)
    item_id = db.Column(db.String(255))
    status = db.Column(db.String(20))
    web_browser = db.Column(db.String(50))
    addon_type = db.Column(db.String(30))
    name = db.Column(db.String(1000))
    version = db.Column(db.String(50))
    title = db.Column(db.String(1000))
    install_time = db.Column(db.DateTime, default=datetime.now())
    addon_filename = db.Column(db.String(1000))

    def __init__(self, employee_id, campaign_id, item_id, status, web_browser, addon_type, name, version, title,
                 install_time, addon_filename):
        self.employee_id = employee_id
        self.campaign_id = campaign_id
        self.item_id = item_id
        self.status = status
        self.web_browser = web_browser
        self.addon_type = addon_type
        self.name = name
        self.version = version
        self.title = title
        self.install_time = install_time
        self.addon_filename = addon_filename

    def __repr__(self):
        return '<Addons {}>'.format(self.id)


class Files(db.Model):
    __tablename__ = 'rp_files'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(10), nullable=False)
    campaign_id = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(1024))
    verified = db.Column(db.String(100))
    date = db.Column(db.DateTime, default=datetime.now())
    publisher = db.Column(db.String(255))
    product_version = db.Column(db.String(128))
    entropy = db.Column(db.String(10))
    md5_hash = db.Column(db.String(65))
    sha1_hash = db.Column(db.String(65))
    sha256_hash = db.Column(db.String(65))
    virustotal = db.Column(db.String(10), default='updating')

    def __init__(self, employee_id, campaign_id, path, verified, date, publisher, product_version, entropy, md5_hash,
                 sha1_hash, sha256_hash, virustotal):
        self.employee_id = employee_id
        self.campaign_id = campaign_id
        self.path = path
        self.verified = verified
        self.date = date
        self.publisher = publisher
        self.product_version = product_version
        self.entropy = entropy
        self.md5_hash = md5_hash
        self.sha1_hash = sha1_hash
        self.sha256_hash = sha256_hash
        self.virustotal = virustotal

    def __repr__(self):
        return '<Files {}>'.format(self.id)


class Info(db.Model):
    __tablename__ = 'rp_info'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(10), nullable=False)
    campaign_id = db.Column(db.String(10), nullable=False)
    host_name = db.Column(db.String(50))
    os_name = db.Column(db.String(100))
    os_version = db.Column(db.String(100))
    registered_owner = db.Column(db.String(30))
    original_install_date = db.Column(db.DateTime, default=datetime.now())
    system_manufacturer = db.Column(db.String(100))
    system_type = db.Column(db.String(100))
    processor = db.Column(db.String(255))
    total_physical_memory = db.Column(db.String(20))
    domain = db.Column(db.String(100))
    hotfix = db.Column(db.String(4096))
    network_card = db.Column(db.String(4096))
    macaddress = db.Column(db.String(1024))  # 65535

    def __init__(self, employee_id, campaign_id, host_name, os_name, os_version, registered_owner,
                 original_install_date, system_manufacturer,
                 system_type, processor, total_physical_memory, domain, hotfix, network_card, macaddress):
        self.employee_id = employee_id
        self.campaign_id = campaign_id
        self.host_name = host_name
        self.os_name = os_name
        self.os_version = os_version
        self.registered_owner = registered_owner
        self.original_install_date = original_install_date
        self.system_manufacturer = system_manufacturer
        self.system_type = system_type
        self.processor = processor
        self.total_physical_memory = total_physical_memory
        self.domain = domain
        self.hotfix = hotfix
        self.network_card = network_card
        self.macaddress = macaddress

    def __repr__(self):
        return '<Info {}>'.format(self.id)


class Networking(db.Model):
    __tablename__ = 'rp_networking'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(10), nullable=False)
    campaign_id = db.Column(db.String(10), nullable=False)
    process_name = db.Column(db.String(50))
    pid = db.Column(db.String(10))
    local_address = db.Column(db.String(100))
    local_port = db.Column(db.String(10))
    remote_address = db.Column(db.String(100))
    remote_port = db.Column(db.String(10))
    state = db.Column(db.String(50))

    def __init__(self, employee_id, campaign_id, process_name, pid, local_address, local_port, remote_address,
                 remote_port, state):
        self.employee_id = employee_id
        self.campaign_id = campaign_id
        self.process_name = process_name
        self.pid = pid
        self.local_address = local_address
        self.local_port = local_port
        self.remote_address = remote_address
        self.remote_port = remote_port
        self.state = state

    def __repr__(self):
        return '<Networking {}>'.format(self.id)


class Process(db.Model):
    __tablename__ = 'rp_process'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(10), nullable=False)
    campaign_id = db.Column(db.String(10), nullable=False)
    pid = db.Column(db.String(10))
    process_name = db.Column(db.String(100))
    username = db.Column(db.String(100))
    description = db.Column(db.String(100))
    company = db.Column(db.String(100))
    verified = db.Column(db.String(100))
    md5_hash = db.Column(db.String(65))
    sha1_hash = db.Column(db.String(65))
    sha256_hash = db.Column(db.String(65))
    command_line = db.Column(db.String(10240))
    path = db.Column(db.String(1024))  # 65535
    virustotal = db.Column(db.String(10), default='updating')

    def __init__(self, employee_id, campaign_id, pid, process_name, username, description, company, verified, md5_hash,
                 sha1_hash, sha256_hash, command_line, path, virustotal):
        self.employee_id = employee_id
        self.campaign_id = campaign_id
        self.pid = pid
        self.process_name = process_name
        self.username = username
        self.description = description
        self.company = company
        self.verified = verified
        self.md5_hash = md5_hash
        self.sha1_hash = sha1_hash
        self.sha256_hash = sha256_hash
        self.command_line = command_line
        self.path = path
        self.virustotal = virustotal

    def __repr__(self):
        return '<Process {}>'.format(self.id)


class EventLogs(db.Model):
    __tablename__ = 'rp_eventlogs'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(10), nullable=False)
    campaign_id = db.Column(db.String(10), nullable=False)
    event_id = db.Column(db.String(10))
    time_created = db.Column(db.DateTime, default=datetime.now())
    log_name = db.Column(db.String(50))
    process_id = db.Column(db.String(10))
    level_display_name = db.Column(db.String(50))
    message = db.Column(db.String(4096))  # 21844

    def __init__(self, employee_id, campaign_id, event_id, time_created, log_name, process_id, level_display_name,
                 message):
        self.employee_id = employee_id
        self.campaign_id = campaign_id
        self.event_id = event_id
        self.time_created = time_created
        self.log_name = log_name
        self.process_id = process_id
        self.level_display_name = level_display_name
        self.message = message

    def __repr__(self):
        return '<EventLogs {}>'.format(self.id)


class LastActivity(db.Model):
    __tablename__ = 'rp_lastactivity'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(10), nullable=False)
    campaign_id = db.Column(db.String(10), nullable=False)
    action_time = db.Column(db.DateTime, default=datetime.now())
    description = db.Column(db.String(255))
    filename = db.Column(db.String(100))
    full_path = db.Column(db.String(1024))  # 65535
    more_information = db.Column(db.String(2048))  # 65535
    file_extension = db.Column(db.String(10))
    data_source = db.Column(db.String(255))

    def __init__(self, employee_id, campaign_id, action_time, description, filename, full_path, more_information,
                 file_extension, data_source):
        self.employee_id = employee_id
        self.campaign_id = campaign_id
        self.action_time = action_time
        self.description = description
        self.filename = filename
        self.full_path = full_path
        self.more_information = more_information
        self.file_extension = file_extension
        self.data_source = data_source

    def __repr__(self):
        return '<LastActivity {}>'.format(self.id)


class Virustotal(db.Model):
    __tablename__ = 'rp_virustotal'
    id = db.Column(db.Integer, primary_key=True)
    md5_hash = db.Column(db.String(32), nullable=False, unique=True)
    sha1_hash = db.Column(db.String(40), nullable=False, unique=True)
    sha256_hash = db.Column(db.String(64), nullable=False, unique=True)
    detection_ratio = db.Column(db.String(10), default='updating')
    last_update = db.Column(db.DateTime, default=datetime.now())

    def __init__(self, md5_hash, sha1_hash, sha256_hash, detection_ratio):
        self.md5_hash = md5_hash
        self.sha1_hash = sha1_hash
        self.sha256_hash = sha256_hash
        self.detection_ratio = detection_ratio

    def __repr__(self):
        return '<Virustotal {}>'.format(self.id)


class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    password = db.Column(db.String(255))

    def __init__(self, username, passwords):
        self.username = username
        self.set_password(passwords)

    def set_password(self, passwords):
        self.password = generate_password_hash(passwords)

    def check_password(self, passwords):
        return check_password_hash(self.password, passwords)


class Comment(db.Model):
    __tablename__ = 'rp_comment'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(10))
    campaign_id = db.Column(db.String(10))
    username = db.Column(db.String(50))
    content = db.Column(db.String(1000))
    time = db.Column(db.DateTime, default=datetime.now())

    def __init__(self, employee_id, campaign_id, username, content):
        self.employee_id = employee_id
        self.campaign_id = campaign_id
        self.username = username
        self.content = content
