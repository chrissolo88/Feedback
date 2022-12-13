from flask import Flask, request, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import db,connect_db, User, Feedback
from my_secrets import SECRET_KEY
from forms import UserRegisterForm, UserLoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgres:///feedback"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc234"
app.config["DEBUG_TB_INTERCEPT_REDIRECTS"] = False

connect_db(app)
db.create_all()

toolbar = DebugToolbarExtension(app)

@app.route('/')
def redirect_home():
    return redirect('/register')

@app.route('/users/<username>', methods=["GET","POST"])
def show_user(username):
    if 'username' not in session:
        flash('Please Login First', 'danger')
        return redirect('/')
    user = User.query.get_or_404(username)
    if session['username'] != user.username:
        flash('Not Authorized', 'danger')
        return redirect('/') 
    if request.method == "POST" and username == session['username']:
        db.session.delete(user)
        db.session.commit()
        flash('User successfully Deleted!','success')
        return redirect('/logout')    
    user_feedback = Feedback.query.filter_by(username=user.username).all()
    return render_template('user.html', user=user, user_feedback=user_feedback)

@app.route('/users/<username>/feedback', methods=["GET","POST"])
def add_feedback(username):
    if 'username' not in session:
        flash('Please Login First', 'danger')
        return redirect('/')
    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
    
        new_feedback = Feedback(title=title, content=content, username=session['username'])
        db.session.add(new_feedback)
        db.session.commit()
        flash('Feedback submitted','success')
        return redirect(f'/users/{username}')
    return render_template('feedback.html', form=form)

@app.route('/feedback/<int:feedback_id>', methods=["GET","POST"])
def edit_feedback(feedback_id):
    if 'username' not in session:
        flash('Please Login First', 'danger')
        return redirect('/')
    feedback = Feedback.query.get_or_404(feedback_id)
    if session['username'] != feedback.username:
        flash('Not Authorized', 'danger')
        return redirect('/')  
    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        return redirect(f'/users/{feedback.username}')
    return render_template('feedback.html', form=form)

@app.route('/feedback/<int:feedback_id>/delete', methods=["POST"])
def delete_feedback(feedback_id):
    if 'username' not in session:
        flash('Please Login First', 'danger')
        return redirect('/')
    feedback = Feedback.query.get_or_404(feedback_id)
    db.session.delete(feedback)
    db.session.commit()
    flash('Feedback Deleted', 'success')
    return redirect(f'/users/{session["username"]}')

@app.route('/register', methods=["GET","POST"])
def register_user():
    if 'username' in session:
        return redirect(f'/users/{session["username"]}')
    form = UserRegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        
        new_user = User.register(username, password, email, first_name, last_name)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username Taken')
            return render_template('register.html', form=form)
        session['username']= new_user.username
        flash("Welcome! Successfully Created Your Account", "success")
        return redirect(f'/users/{new_user.username}')
    return render_template('register.html', form=form)

@app.route('/login', methods=["GET", "POST"])
def login_user():
    if 'username' in session:
        return redirect(f'/users/{session["username"]}')
    form = UserLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f"Welcome Back {user.username}!", "success")
            session['username']= user.username
            return redirect(f'/users/{user.username}')
        else:
            form.username.errors = ['Invalid Username/Password']
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)

@app.route('/logout')
def logout_user():
    session.pop('username')
    return redirect('/')