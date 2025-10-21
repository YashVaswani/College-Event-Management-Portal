# 1.Imports
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# 2.App Initialization and Configuration 
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_change_me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///events.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 3.Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 4. Database Models
registrations = db.Table('registrations',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('event_id', db.Integer, db.ForeignKey('event.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    registered_events = db.relationship('Event', secondary=registrations, backref='attendees')

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    time = db.Column(db.String(50), nullable=True)
    location = db.Column(db.String(200), nullable=True)
    category = db.Column(db.String(50), nullable=True)
    description = db.Column(db.Text, nullable=True)

class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Query(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 5. Routes

#  Main & Public Routes 
@app.route('/')
def index():
    search_term = request.args.get('search')
    category_filter = request.args.get('category')
    query = Event.query
    if category_filter:
        query = query.filter(Event.category == category_filter)
    if search_term:
        query = query.filter(or_(Event.name.ilike(f'%{search_term}%'), Event.description.ilike(f'%{search_term}%')))
    events = query.order_by(Event.date).all()
    latest_notices = Notice.query.order_by(Notice.date_posted.desc()).limit(3).all()
    return render_template('index.html', events=events, search_term=search_term, notices=latest_notices)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        new_query = Query(name=request.form['name'], email=request.form['email'], subject=request.form['subject'], message=request.form['message'])
        db.session.add(new_query)
        db.session.commit()
        flash('Your query has been sent successfully!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

#  Student Authentication & Actions 
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    if request.method == 'POST':
        new_feedback = Feedback(rating=request.form['rating'], comment=request.form['comment'], user_id=current_user.id)
        db.session.add(new_feedback)
        db.session.commit()
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('index'))
    return render_template('feedback.html')

@app.route('/my_events')
@login_required
def my_events():
    return render_template('my_events.html', events=current_user.registered_events)

@app.route('/register_event/<int:event_id>')
@login_required
def register_event(event_id):
    event = Event.query.get_or_404(event_id)
    if event not in current_user.registered_events:
        current_user.registered_events.append(event)
        db.session.commit()
        flash(f'You have successfully registered for "{event.name}"!', 'success')
    else:
        flash(f'You are already registered for "{event.name}".', 'info')
    return redirect(url_for('index'))

@app.route('/unregister_event/<int:event_id>')
@login_required
def unregister_event(event_id):
    event = Event.query.get_or_404(event_id)
    if event in current_user.registered_events:
        current_user.registered_events.remove(event)
        db.session.commit()
        flash(f'You have successfully unregistered from "{event.name}".', 'success')
    else:
        flash(f'You were not registered for "{event.name}".', 'info')
    return redirect(url_for('index'))

#  Admin Routes 
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have permission to access the admin panel.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        if 'event_submit' in request.form:
            new_event = Event(name=request.form['name'], date=request.form['date'], time=request.form['time'], location=request.form['location'], category=request.form['category'], description=request.form['description'])
            db.session.add(new_event)
            db.session.commit()
            flash('Event added successfully!', 'success')
            return redirect(url_for('admin'))
        if 'notice_submit' in request.form:
            new_notice = Notice(title=request.form['title'], content=request.form['content'])
            db.session.add(new_notice)
            db.session.commit()
            flash('Notice posted successfully!', 'success')
            return redirect(url_for('admin'))

    all_events = Event.query.order_by(Event.date).all()
    all_notices = Notice.query.order_by(Notice.date_posted.desc()).all()
    all_queries = Query.query.order_by(Query.timestamp.desc()).all()
    all_feedback = Feedback.query.order_by(Feedback.timestamp.desc()).all()
    return render_template('admin.html', events=all_events, notices=all_notices, queries=all_queries, feedbacks=all_feedback)

@app.route('/edit_event/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_event(id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    event_to_edit = Event.query.get_or_404(id)
    if request.method == 'POST':
        event_to_edit.name = request.form['name']
        event_to_edit.date = request.form['date']
        event_to_edit.time = request.form['time']
        event_to_edit.location = request.form['location']
        event_to_edit.category = request.form['category']
        event_to_edit.description = request.form['description']
        db.session.commit()
        flash('Event updated successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_event.html', event=event_to_edit)

@app.route('/edit_notice/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_notice(id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    notice_to_edit = Notice.query.get_or_404(id)
    if request.method == 'POST':
        notice_to_edit.title = request.form['title']
        notice_to_edit.content = request.form['content']
        db.session.commit()
        flash('Notice updated successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_notice.html', notice=notice_to_edit)

@app.route('/view_attendees/<int:event_id>')
@login_required
def view_attendees(event_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))
    event = Event.query.get_or_404(event_id)
    attendees = event.attendees
    return render_template('view_attendees.html', event=event, attendees=attendees)

@app.route('/delete_event/<int:id>')
@login_required
def delete_event(id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    event_to_delete = Event.query.get_or_404(id)
    db.session.delete(event_to_delete)
    db.session.commit()
    flash('Event deleted successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/delete_notice/<int:id>')
@login_required
def delete_notice(id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    notice_to_delete = Notice.query.get_or_404(id)
    db.session.delete(notice_to_delete)
    db.session.commit()
    flash('Notice deleted!', 'success')
    return redirect(url_for('admin'))

# 6. Main Execution Block
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)