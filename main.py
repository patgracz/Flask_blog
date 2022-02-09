from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import flask_login as fl
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
login_manager.init_app(app)

db = SQLAlchemy(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
# Line below only required once, when creating DB.
# db.create_all()


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = request.form
    if form:
        if db.session.query(User).filter_by(email=form['email']).first():
            flash('Your Email adress already exists in our database, try to log in')
            return redirect(url_for('login'))

        new_user = User(
            email=form['email'],
            password=generate_password_hash(password=form['password'], method='pbkdf2:sha256', salt_length=8),
            name=form['name'],
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('secrets', name=new_user.name))

    return render_template("register.html")


@app.route('/login', methods=['POST', 'GET'])
def login():

    if request.method == 'POST':
        user = request.form['email']
        our_user = db.session.query(User).filter_by(email=user).first()
        if our_user:
            password = request.form['password']
            if check_password_hash(our_user.password, password=password):
                login_user(our_user)

                return redirect(url_for('secrets'))
            else:
                flash('Invalid password')
                return redirect(url_for('login'))
        flash('Your email adress is invalid')
    return render_template("login.html")

@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")



@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static/files', filename='cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
