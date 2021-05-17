from flask import (Flask, render_template, g, request, session)
from flask.helpers import url_for
from werkzeug.utils import redirect, secure_filename
from Database.database import get_db
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


def get_current_user():
    user_result = None

    if 'user' in session:
        # get user cookie
        user_cookie = session['user']

        db = get_db()

        # get username and password from database where name equal to username login
        user_cur = db.execute(
            'SELECT name, password, expert, admin FROM users WHERE name = ?', [user_cookie])
        user_result = user_cur.fetchone()

    return user_result


@app.route('/')
def index():
    user = get_current_user()

    return render_template('home.html', user=user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db = get_db()

        hashed_password = generate_password_hash(
            request.form['password'], method='sha256')  # make hash password

        # insert data from /register POST to user table in database and create a user
        db.execute('INSERT INTO users (name, password, expert, admin) VALUES (?, ?, ?, ?)', [
            request.form['name'], hashed_password, '0', '0'])
        db.commit()

        session['user'] = request.form['name']

        return redirect(url_for('index'))

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        db = get_db()

        # get username and pass from user Login
        name = request.form['name']
        password = request.form['password']

        # get username and password from database where name equal to username login
        user_cur = db.execute(
            'SELECT name, password FROM users WHERE name = ?', [name])
        user_result = user_cur.fetchone()

        # check user password
        if user_result and check_password_hash(user_result['password'], password):
            session['user'] = user_result['name']
            return redirect(url_for('index'))
        else:
            return redirect('login')

    return render_template('login.html')


@app.route('/question')
def question():
    user = get_current_user()

    return render_template('question.html', user=user)


@app.route('/answer')
def answer():
    user = get_current_user()

    return render_template('answer.html', user=user)


@app.route('/ask')
def ask():
    user = get_current_user()

    return render_template('ask.html', user=user)


@app.route('/unanswered')
def unanswered():
    user = get_current_user()

    return render_template('unanswered.html', user=user)


@app.route('/users')
def users():
    user = get_current_user()

    db = get_db()

    # get list of all the users
    users_cur = db.execute('SELECT id, name, expert, admin FROM users')
    users_results = users_cur.fetchall()

    return render_template('users.html', user=user, users=users_results)

@app.route('/promote/<user_id>')
def promote(user_id):
    db = get_db()

    # promote a user to expert
    db.execute('UPDATE users SET expert = 1 WHERE id = ?', [user_id])
    db.commit()
    return redirect(url_for('users'))


@app.route('/logout')
def logout():
    # destroy session
    session.pop('user', None)

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
