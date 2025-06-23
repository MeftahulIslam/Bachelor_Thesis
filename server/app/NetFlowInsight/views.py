from flask import Blueprint,render_template, request, flash, redirect, url_for, jsonify, send_from_directory, copy_current_request_context
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from .models import User, Notes, PcapLoc, FileAnalysis, FileResult, LogAnalysis
from . import db
import os, json
from .file_operations.file_analysis import run_analysis 
from .log_analysis.log_analysis import LogAnalysisModel
import time

views = Blueprint('views', __name__)

ALLOWED_EXTENSIONS = {'pcap'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@views.route('/')
@login_required
def home():
    return render_template("home.html", user=current_user)

@views.route('/upload', methods=['POST'])
@login_required
def upload():
    start_time = time.time()
    file = request.files['pcap_file']
    if not file or not allowed_file(file.filename):
        flash('Please include a .pcap file',category='error')
    else:
        user_directory = current_user.path
        api_key = current_user.api_key
        filename = secure_filename(file.filename)
        pcap_directory = os.path.join(str(user_directory),filename)
        if not os.path.exists(pcap_directory):
            os.makedirs(pcap_directory)        
        file_path = os.path.join(str(pcap_directory), filename)

        try:
            file.save(file_path)
            new_file = PcapLoc(path=file_path, filename=filename ,user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()

            pcap_loc_id = new_file.id

            log_analysis_result = LogAnalysisModel(pcap_directory, filename)
            log_analysis_result = log_analysis_result.create_test_data()
            log_analysis = LogAnalysis(path=str(file_path), pcap_loc_id = pcap_loc_id, filename = str(filename), result = log_analysis_result)
            db.session.add(log_analysis)
            db.session.commit()

            file_analysis_path, file_paths, mime_types, file_results, filenames, extension_types = run_analysis(file_path,str(pcap_directory), api_key)
            if not file_analysis_path:
                file_analysis = FileAnalysis(path="No Files Detected in the Pcap File!", pcap_loc_id=pcap_loc_id)
                db.session.add(file_analysis)
                db.session.commit()
            else:
                file_analysis = FileAnalysis(path=str(file_analysis_path), pcap_loc_id=pcap_loc_id)
                db.session.add(file_analysis)
                db.session.commit()
                file_analysis_id = file_analysis.id
                for file_path,mime_type,file_result,file_name,extension_type in zip(file_paths, mime_types, file_results, filenames, extension_types):
                    file_result_new = FileResult(filepath = str(file_path), mime_type=mime_type, result=file_result, filename=file_name, extension_type=extension_type, file_analysis_id = file_analysis_id)
                    db.session.add(file_result_new)
                db.session.commit()
                
            flash(f'File uploaded successfully!', category='success')
            analysis_time = round(time.time() - start_time, 1)
            print(analysis_time)
        except Exception as e:
            flash(f'{e}', category='error')


    return redirect(url_for('views.home',user=current_user))




    
@views.route('file_analysis_results/',methods=['GET','POST'])
@login_required
def file_analysis_results():
    return render_template("file_analysis_results.html",user=current_user)

@views.route('/download/<path:file_path>')
@login_required
def download_file(file_path):
    # Ensure 'file_path' is sanitized to prevent path traversal attacks
    # Send the file for download
    return send_from_directory(directory='/',path=file_path, as_attachment=True)

@views.route('profile/', methods=['GET','POST'])
@login_required
def profile():
    return render_template("profile.html", user=current_user)


@views.route('/update_api_key', methods=['POST'])
@login_required
def update_api_key():
    new_api_key = request.json.get('api_key')

    # Update the API key in your backend
    # Perform necessary actions (e.g., update in the database)

    # For example, updating a variable in this example
    try:
        user = User.query.get(current_user.id)
        if user:
            user.api_key = new_api_key
            db.session.commit()
        else:
            raise ValueError('User not found! Unknown error!')

    except Exception as e:
        flash(f'{e}', category='error')

    # You can return a response if needed
    return jsonify({})


@views.route('/update_notes', methods=['POST'])
@login_required
def update_notes():
    new_note = request.json.get('note')
    note_id = request.json.get('note_id')

    # Update the API key in your backend
    # Perform necessary actions (e.g., update in the database)

    # For example, updating a variable in this example
    try:
        note = Notes.query.get(note_id)
        if note:
            note.note = new_note
            db.session.commit()
        else:
            raise ValueError('Note not found! Unknown error!')

    except Exception as e:
        flash(f'{e}', category='error')

    # You can return a response if needed
    return jsonify({})

@views.route('delete_note/', methods=['POST'])
@login_required
def delete_note():
    note = json.loads(request.data) 
    note_id = note['note_id']
    note = Notes.query.get(note_id)
    if note:
        db.session.delete(note)
        db.session.commit()
    return jsonify({})

@views.route('view_notes/',methods=['GET','POST'])
@login_required
def view_notes():
    if request.method == 'POST':
        note = request.form.get('note')
        file_id = request.form.get('file_id')
        if len(note) < 1:
            flash('Empty Note!', category='error')
        else:
            new_note = Notes(note=note, pcap_loc_id = file_id)
            flash('New note added successfully!', category='success')
            db.session.add(new_note)
            db.session.commit()

    return render_template("view_notes.html", user=current_user)