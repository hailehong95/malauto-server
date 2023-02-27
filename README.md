## MalAuto Server


### Update system

- Make sure the system is up to date
  ```bash
  $ sudo apt-get -y update
  $ sudo apt-get -y upgrade
  ```

### MySQL Server

- Install and configure MySQL
  ```bash
  $ sudo apt-get install -y mysql-server mysql-client
  ```

- Set root password
  ```bash
  $ sudo mysql -u root
  Welcome to the MySQL monitor.  Commands end with ; or \g.
  Your MySQL connection id is 13
  Server version: 8.0.31-0ubuntu0.22.04.1 (Ubuntu)
  ...  
  mysql> ALTER USER 'root'@'localhost' IDENTIFIED WITH caching_sha2_password BY '<YOUR-PASSWORD>';
  Query OK, 0 rows affected (0.02 sec)
  
  mysql> SELECT Host, User, plugin FROM mysql.user;
  +-----------+------------------+-----------------------+
  | Host      | User             | plugin                |
  +-----------+------------------+-----------------------+
  | localhost | debian-sys-maint | caching_sha2_password |
  | localhost | mysql.infoschema | caching_sha2_password |
  | localhost | mysql.session    | caching_sha2_password |
  | localhost | mysql.sys        | caching_sha2_password |
  | localhost | root             | caching_sha2_password |
  +-----------+------------------+-----------------------+
  5 rows in set (0.00 sec)
  ```

- Basic security settings for MySQL
  ```bash
  $ sudo mysql_secure_installation
  - Change the password for root ? ((Press y|Y for Yes, any other key for No) : n
  - Remove anonymous users? (Press y|Y for Yes, any other key for No) : y
  - Disallow root login remotely? (Press y|Y for Yes, any other key for No) : y
  - Remove test database and access to it? (Press y|Y for Yes, any other key for No) : y
  - Reload privilege tables now? (Press y|Y for Yes, any other key for No) : y
  ```

### Python v3

- Install Python3 and packages
  ```bash
  $ sudo apt-get install -y python3-dev python3-pip python3-venv
  $ python3 -V
  Python 3.10.6
  $ pip3 -V
  pip 22.2.2 from /usr/local/lib/python3.10/dist-packages/pip (python 3.10)
  ```

### Nginx Server

- Install Nginx web server
  ```bash
  $ sudo apt-get install -y nginx
  $ nginx -V
  nginx version: nginx/1.18.0 (Ubuntu)
  built with OpenSSL 3.0.2 15 Mar 2022
  ```

### Redis Server

- Install Redis
  ```bash
  $ sudo apt-get install -y redis-server
  $ redis-server -v
  Redis server v=6.0.16 sha=00000000:0 malloc=jemalloc-5.2.1 bits=64 build=a3fdef44459b3ad6
  ```

### Setup autostart services

- Enable startup
  ```bash
  $ sudo systemctl enable mysql.service
  $ sudo systemctl restart mysql.service
  
  $ sudo systemctl enable nginx.service
  $ sudo systemctl restart nginx.service
  
  $ sudo systemctl enable redis-server.service
  $ sudo systemctl restart redis-server.service
  ```

- Check
  ```bash
  $ sudo netstat -ltpnd | grep -i "nginx\|mysql\|redis" | sort
  tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      5925/nginx: master
  tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      5867/mysqld
  tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      5867/mysqld
  tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      5937/redis-server 1
  tcp6       0      0 ::1:6379                :::*                    LISTEN      5937/redis-server 1
  tcp6       0      0 :::80                   :::*                    LISTEN      5925/nginx: master
  ```

### Download and install MalAuto

- Clone source
  ```bash
  $ cd /opt/
  $ git clone https://github.com/hailehong95/malauto-server.git
  ```

- Install python packages
  ```bash
  $ cd malauto-server
  $ python3 -m venv venv
  $ sudo apt install -y libmysqlclient-dev
  $ source venv/bin/activate
  (venv) $ python3 -m pip install -r requirements.txt
  ```

- Create DB
  ```bash
  $ mysql -u root -p
  mysql> create user 'malauto'@'localhost' identified by '<Your-Password>';
  mysql> create database malauto CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
  mysql> grant all privileges on malauto.* to 'malauto'@'localhost';
  mysql> flush privileges;
  mysql> quit
  ```

- Edit config `.env`
  ```bash
  # Database config
  MYSQL_DB_NAME=<ChangeMe>
  MYSQL_HOST=<ChangeMe>
  MYSQL_USER=<ChangeMe>
  MYSQL_USER_PASSWORD=<ChangeMe>
  
  # App config
  SECRET_KEY=<Random-32-characters>
  # UPLOAD_DIR=<Optional, not require>
  # size in byte: 30MB
  MAX_CONTENT_LENGTH=31457280
  ALLOWED_EXTENSIONS=zip,7z,tar,gz
  TELEGRAM_CHAT_ID=<ChangeMe>
  TELEGRAM_BOT_TOKEN=<ChangeMe>
  
  # Redis config
  REPORT_QUEUE_NAME=report
  VIRUSTOTAL_QUEUE_NAME=virustotal
  
  # VT Config
  SYS_INTERNAL_VT_API=<ChangeMe>
  ```

- Migrate DB
  ```bash
  (venv) $ export FLASK_APP=malauto.py
  (venv) $ export FLASK_ENV=development
  (venv) $ flask db init
  (venv) $ flask db migrate -m "create table"
  (venv) $ flask db upgrade
  ```

- re-check in DB
  ```bash
  mysql> use malauto;
  Database changed
  mysql> show tables;
  +-------------------+
  | Tables_in_malauto |
  +-------------------+
  | alembic_version   |
  | campaign_info     |
  | employee_info     |
  | rp_addons         |
  | rp_autoruns       |
  | rp_comment        |
  | rp_eventlogs      |
  | rp_files          |
  | rp_info           |
  | rp_lastactivity   |
  | rp_networking     |
  | rp_process        |
  | rp_virustotal     |
  | users             |
  +-------------------+
  14 rows in set (0.00 sec)
  ```


- Run MalAuto server
  ```bash
  $ python malauto.py
  * Serving Flask app 'malauto.config'
  * Debug mode: off
  WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
  * Running on http://127.0.0.1:5000
  Press CTRL+C to quit
  ```

### Managing services with Systemd

- MalAuto Service: `/etc/systemd/system/malauto.service`
  ```bash
  [Unit]
  Description=Malware Automation Check Server Application
  After=network.target
  
  [Service]
  User=www-data
  Group=www-data
  WorkingDirectory=/opt/malauto-server
  Environment="PATH=/opt/malauto-server/venv/bin"
  
  ExecStart=/opt/malauto-server/venv/bin/gunicorn -b unix:app.sock -m 007 -w 4 malauto:app
  Restart=always
  
  [Install]
  WantedBy=multi-user.target
  ```

- RQ Dashboard: `/etc/systemd/system/rq-dashboard.service`
  ```bash
  [Unit]
  Description=RQ Dashboard Flask server
  After=network.target
  
  [Service]
  User=www-data
  Group=www-data
  WorkingDirectory=/opt/malauto-server
  Environment="PATH=/opt/malauto-server/venv/bin"
  
  ExecStart=/opt/malauto-server/venv/bin/rq-dashboard -b 127.0.0.1 -p <Your-Port> --username <Your-Username> --password <Your-Password>
  Restart=always
  
  [Install]
  WantedBy=multi-user.target
  ```

- Report Worker: `/etc/systemd/system/report-worker@.service`
  ```bash
  [Unit]
  Description=Malware Automation Check Report Worker %I
  After=network.target
  
  [Service]
  User=www-data
  Group=www-data
  WorkingDirectory=/opt/malauto-server
  Environment="PATH=/opt/malauto-server/venv/bin"
  
  ExecStart=/opt/malauto-server/venv/bin/rq worker report
  Restart=always
  
  [Install]
  WantedBy=multi-user.target
  ```

- Virustotal Worker: `/etc/systemd/system/virustotal-worker@.service`
  ```bash
  [Unit]
  Description=Malware Automation Check Virustotal Worker %I
  After=network.target
  
  [Service]
  User=www-data
  Group=www-data
  WorkingDirectory=/opt/malauto-server
  Environment="PATH=/opt/malauto-server/venv/bin"
  
  ExecStart=/opt/malauto-server/venv/bin/rq worker virustotal
  Restart=always
  
  [Install]
  WantedBy=multi-user.target
  ```

- Permissions
    - `Web` directory
  ```bash
  $ sudo chown -R www-data:www-data /opt/malauto-server/
  ```

    - `upload` directory
  ```bash
  $ sudo mkdir -p /opt/upload
  $ sudo chown -R www-data:www-data /opt/upload/
  ```

### Use Nginx as a reverse proxy

- Reverse proxy for MalAuto

  ```bash
  server {
      listen 80;
      server_name _;
      server_tokens off;
  
      # Upload file limit
      client_max_body_size 30M;
  
      # Logs file config
      access_log /var/log/nginx/malauto-access.log;
      error_log /var/log/nginx/malauto-error.log;
  
      # Proxy config
      location /
      {
          proxy_set_header Host $http_host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto $scheme;
          proxy_pass http://unix:/opt/malauto-server/app.sock;
      }
  
      location /static
      {
          alias /opt/malauto-server/malauto/static;
          expires 30d;
      }
  }
  ```

- Reverse proxy for Redis Queue dashboard

  ```bash
  server {
      listen 8081;
      server_name _;
      server_tokens off;
  
      # Logs file config
      access_log /var/log/nginx/rq-dashboard-access.log;
      error_log /var/log/nginx/rq-dashboard-error.log;
  
      # Proxy config
      location /
      {
          proxy_pass http://127.0.0.1:<Your-Port>;
          proxy_redirect off;
          proxy_set_header Host $host;
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      }
  }
  ```

### Starting service

- Reload to update new script
  ```bash
  $ sudo systemctl daemon-reload
  ```

- Start MalAuto

  ```bash
  $ sudo systemctl enable malauto.service
  $ sudo systemctl start malauto.service
  ```

- Start RQ Dashboard

  ```bash
  $ sudo systemctl enable rq-dashboard.service
  $ sudo systemctl start rq-dashboard.service
  ```

- Start Report Worker

  ```bash
  $ sudo systemctl enable report-worker@service
  $ sudo systemctl start report-worker@{1..5}
  ```

- Start Virustotal Worker

  ```bash
  $ sudo systemctl enable virustotal-worker@service
  $ sudo systemctl start virustotal-worker@{1..5}
  ```

- Restart Nginx

  ```bash
  $ sudo nginx -t
  $ sudo systemctl restart nginx.service
  ```

### Checking

- Test add campaign

  ```bash
  $ curl -X POST -H "Content-Type: application/json" \
      --data '{"campaign_id":"cp02","campaign_name":"Kết quả đợt 2 năm 2022","start_date":"2022-11-29","end_date":"2022-12-31"}' \
      http://127.0.0.1/addcp
  ```

- Test register

  ```bash
  $ curl -X POST -H "Content-Type: application/json" \
      --data '{"employee_id":"123456","full_name":"Nguyen Van An","report_name":"123456_NguyenVanAn_k24wg.zip","group_name":"HN-T04","platform":"Windows"}' \
      http://127.0.0.1/register
  ```

- Test upload report

  ```bash
  $ curl -X POST -L \
      -F "metadata={name : '123456_NguyenVanAn_k24wg.zip'};type=application/json;charset=UTF-8" \
      -F "file=@123456_NguyenVanAn_k24wg.zip;type=application/zip" \
      "http://127.0.0.1/files"
  ```

- Create new users

  ```bash
  (venv) $ flask shell
  >>> from malauto.config import app
  >>> from malauto.models import *
  >>> 
  >>> new_user = Users('test','S3kret-Passw0rd!')
  >>> db.session.add(new_user)
  >>> db.session.commit()
  >>> 
  ```
