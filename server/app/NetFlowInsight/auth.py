from flask import Blueprint,render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
import os, random

auth = Blueprint('auth', __name__)

@auth.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        api_key = request.form.get('api_key')
        user_exists = User.query.filter_by(email=email).first()

        if len(email) < 4:
            flash('Incorrect email format.', category='error')
        elif len(firstname) < 2: 
            flash('Firstname must be longer than a character', category='error')
        elif len(lastname) < 2:
            flash('Lastname must be longer than a character', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match', category='error')
        elif len(password1) < 7: 
            flash('Password must be longer than 8 characters', category='error')
        elif user_exists:
            flash('An user with the username already exists! Please choose another username!', category='error')
        else:
            try:
                user = firstname + "_" + str(random.random())
                base_directory = os.path.abspath('/opt/uploads/Files')
                user_directory = os.path.join(base_directory, user)
                if not os.path.exists(user_directory):
                    os.makedirs(user_directory)
                
                new_user = User(email = email, firstname = firstname, lastname = lastname, password = generate_password_hash(password1, method='pbkdf2:sha256'), path=user_directory, api_key = api_key)
                db.session.add(new_user)
                db.session.commit()
                #creating a user directory on the server for storing the files

                flash('Account created successfully!', category='success')
                return redirect(url_for('auth.login'))

            except Exception as e:
                flash(f'{e}', category='error')
    return render_template("signup.html",user=current_user)

@auth.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            flash('Logged in successfully!', category='success')
            login_user(user,remember=True)
            return redirect(url_for('views.home', user=current_user))
        else:
            flash('Username or password incorrect!', category='error')
            return render_template("login.html",email = f"{email}", user=current_user)
    return render_template("login.html", user=current_user)

@auth.route("logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))