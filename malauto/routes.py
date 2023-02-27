import os

from datetime import datetime
from werkzeug.utils import secure_filename
from flask import request, redirect, jsonify
from flask import render_template, url_for, session

from malauto.config import queue_report
from malauto.forms import LoginForm, CategoryForm, CommentForm
from malauto.tasks import get_current_campaign, report_background_task
from malauto.models import Info, Networking, Process, EventLogs, LastActivity
from malauto.models import Employee, Campaign, Autoruns, Addons, Files, Users, Comment
from malauto.utils import is_allow_file, malauto_send_telegram, convert_size, create_directory

from malauto.config import app, db
from malauto.config import csrf

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'Employee': Employee, 'Campaign': Campaign}


@app.route('/', methods=['GET'])
def dashboard():
    try:
        if 'username' not in session:
            return redirect(url_for('login'))
        campaign_items = db.session.query(Campaign).all()
        if campaign_items:
            return render_template("index.html", campaign_list=campaign_items)
        return redirect('/', code=302)
    except Exception as ex:
        print(ex)


@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        form = LoginForm()
        if 'username' in session:
            return redirect(url_for('dashboard'))
        if request.method == 'GET':
            return render_template("login.html", form=form)
        if request.method == 'POST':
            user_item = Users.query.filter_by(username=form.username.data).first()
            if user_item and user_item.check_password(form.password.data):
                session['username'] = form.username.data
                return redirect(url_for('dashboard'))
            else:
                errors = "Thông tin đăng nhập không chính xác."
                return render_template("login.html", form=form, errors=errors)
    except Exception as ex:
        print(ex)
        return render_template("login.html", form=form)


@app.route('/logout', methods=['GET'])
def logout():
    try:
        if 'username' not in session:
            return redirect(url_for('login'))
        session.pop('username')
        return redirect(url_for('login'))
    except Exception as ex:
        print(ex)


@app.route('/<string:cp_id>/', methods=['GET'])
def employee_page(cp_id):
    try:
        if 'username' not in session:
            return redirect(url_for('dashboard'))
        employee_items = db.session.query(Employee).filter_by(campaign_id=cp_id).all()
        if cp_id and employee_items:
            return render_template("campaign.html", employee_list=employee_items)
        return redirect('/', code=302)
    except Exception as ex:
        print(ex)


@app.route('/<string:cp_id>/<string:ep_id>/', methods=['GET', 'POST'])
def report_page(cp_id, ep_id):
    try:
        if 'username' not in session:
            return redirect(url_for('dashboard'))
        ctform = CategoryForm()
        cmform = CommentForm()
        if request.method == 'GET':
            if cp_id and ep_id:
                info_item = db.session.query(Info).filter_by(campaign_id=cp_id, employee_id=ep_id).first()
                employee_item = db.session.query(Employee).filter_by(campaign_id=cp_id, employee_id=ep_id).first()
                autorun_item = db.session.query(Autoruns).filter_by(campaign_id=cp_id, employee_id=ep_id).all()
                process_item = db.session.query(Process).filter_by(campaign_id=cp_id, employee_id=ep_id).all()
                network_item = db.session.query(Networking).filter_by(campaign_id=cp_id, employee_id=ep_id).all()
                file_item = db.session.query(Files).filter_by(campaign_id=cp_id, employee_id=ep_id).all()
                evenlog_item = db.session.query(EventLogs).filter_by(campaign_id=cp_id, employee_id=ep_id).all()
                addon_item = db.session.query(Addons).filter_by(campaign_id=cp_id, employee_id=ep_id).all()
                lastactivity_item = db.session.query(LastActivity).filter_by(campaign_id=cp_id, employee_id=ep_id).all()
                comment_item = db.session.query(Comment).filter_by(campaign_id=cp_id, employee_id=ep_id).all()
                return render_template("report.html", employee_info=info_item, employee_item=employee_item,
                                       autoruns_info=autorun_item, process_info=process_item, network_info=network_item,
                                       files_info=file_item, eventlogs_info=evenlog_item, addons_info=addon_item,
                                       lastactivity_info=lastactivity_item, comment_info=comment_item, ctform=ctform,
                                       cmform=cmform)
        if request.method == 'POST':
            category_submit = ctform.category.data
            comment_content = cmform.content.data
            author_submit = session['username']
            if category_submit:
                print(category_submit)
                update_item = db.session.query(Employee).filter_by(campaign_id=cp_id, employee_id=ep_id).first()
                update_item.result = category_submit
                update_item.verified = author_submit
                db.session.commit()
            if comment_content:
                new_comment = Comment(ep_id, cp_id, author_submit, comment_content)
                db.session.add(new_comment)
                db.session.commit()
            return redirect(url_for('report_page', cp_id=cp_id, ep_id=ep_id))
        return redirect('/', code=302)
    except Exception as ex:
        print(ex)


@app.route('/register', methods=['POST'])
def register_info():
    try:
        json_data = request.get_json()
        employee_id = json_data['employee_id']
        full_name = json_data['full_name']
        status = 'scanning'
        report_name = json_data['report_name']
        report_size = ''
        group_name = json_data['group_name']
        platform = json_data['platform']
        campaign_id = get_current_campaign(datetime.today())
        item = db.session.query(Employee).filter_by(employee_id=employee_id).first()
        if not item:
            new_user = Employee(employee_id, campaign_id, full_name, status, report_name, report_size, group_name, platform)
            db.session.add(new_user)
            db.session.commit()
            resp = jsonify({'message': 'Client has successfully registered'})
            resp.status_code = 201
            return resp
        else:
            resp = jsonify({'message': 'Client has failed registered'})
            resp.status_code = 202
            return resp
    except Exception as ex:
        print(ex)


@app.route('/files', methods=['POST'])
def upload_file():
    try:
        # check if the post request has the file part
        if 'file' not in request.files:
            resp = jsonify({'message': 'No file part in the request'})
            resp.status_code = 400
            return resp
        file = request.files['file']
        if file.filename == '':
            resp = jsonify({'message': 'No file selected for uploading'})
            resp.status_code = 400
            return resp
        if file and is_allow_file(file.filename):
            create_directory(app.config["UPLOAD_DIR"])
            report_name = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_DIR"], report_name))
            report_size = os.stat(os.path.join(app.config["UPLOAD_DIR"], report_name)).st_size
            client_ip = request.remote_addr
            text = f"{client_ip} | {report_name} | {convert_size(report_size)}"
            malauto_send_telegram(text)
            campaign_id = get_current_campaign(datetime.today())
            employee_item = db.session.query(Employee).filter_by(report_name=report_name, campaign_id=campaign_id).first()
            # item = Employee.query.filter_by(report_name=report_name, campaign_id=campaign_id).first()
            if employee_item:
                # push job to queue and update status in db.
                job = queue_report.enqueue(report_background_task, report_name, job_timeout='15m')
                employee_item.status = 'processing'
                employee_item.report_size = convert_size(report_size)
                employee_item.datetime = datetime.now()
                db.session.commit()
            resp = jsonify({'message': 'File successfully uploaded'})
            resp.status_code = 201
            return resp
        else:
            resp = jsonify({'message': 'Allowed file types are zip, scanning'})
            resp.status_code = 400
            return resp
    except Exception as ex:
        print(ex)


@app.route("/addcp", methods=['POST'])
def add_campaign():
    try:
        # return redirect("https://www.google.com.vn/", code=302)
        json_data = request.get_json()
        campaign_id = json_data['campaign_id']
        campaign_name = json_data['campaign_name']
        start_date = datetime.strptime(json_data['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(json_data['end_date'], '%Y-%m-%d')
        campaign_item = db.session.query(Campaign).filter_by(campaign_id=campaign_id).first()
        if not campaign_item:
            new_campaign = Campaign(campaign_id, campaign_name, start_date, end_date)
            db.session.add(new_campaign)
            db.session.commit()
            resp = jsonify({'is_success': 'true'})
            resp.status_code = 201
            return resp
        else:
            resp = jsonify({'is_success': 'failed'})
            resp.status_code = 202
            return resp
    except Exception as ex:
        print(ex)


@app.route("/task", methods=['GET'])
def push_jobs():
    pass
    # For testing background tasks
    if request.args.get('filename'):
        job = queue_report.enqueue(report_background_task, request.args.get('filename'), job_timeout='15m')
        return f"Task ({job.id}) added to queue at {job.enqueued_at}"
    return "No value for count provided"
