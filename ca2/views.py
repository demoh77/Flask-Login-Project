from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .models import Note
from . import db
import json
from markupsafe import escape


views = Blueprint('views', __name__)
auth = Blueprint('auth', __name__)
limiter = Limiter(key_func=get_remote_address)

# Data Input Sanitization
def check_input(text):
    return escape(text.strip())

@views.route('/', methods=['GET', 'POST'])
@views.route('/home', methods=['GET', 'POST'])
@login_required
@limiter.limit("5/minute")
def home():
    if request.method == 'POST': 
        note = check_input(request.form.get('note', '')) # Gets the note from the HTML 

        if len(note) < 1:
            flash('Note is too short!', category='error') 
        else:
            new_note = Note(data=note, user_id=current_user.id)  #providing the schema for the note 
            db.session.add(new_note) #adding the note to the database 
            db.session.commit()
            flash('Your Note is added!', category='success')

    return render_template("home.html", user=current_user)




@views.route('/delete-note', methods=['POST'])
@login_required
@limiter.limit("5/minute")
def delete_note():  
    note = json.loads(request.data) # this function expects a JSON from the INDEX.js file 
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()
            flash('Your Note is deleted!', category='success')

    return jsonify({})
