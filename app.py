from flask import (Flask, render_template, g, request, session, url_for)
from werkzeug.utils import redirect
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
            'SELECT id, name, password, expert, admin FROM users WHERE name = ?', [user_cookie])
        user_result = user_cur.fetchone()

    return user_result


@app.route('/')
def index():
    user = get_current_user()
    db = get_db()

    question_cur = db.execute(
        '''SELECT 
            questions.id,
            questions.questions_text,
            askers.name as asker_name,
            experts.name as expert_name
        FROM questions
        JOIN users as askers ON askers.id = questions.asked_by_id
        JOIN users as experts ON experts.id = questions.expert_id
        WHERE questions.answer_text IS NOT null''')
    question_results = question_cur.fetchall()

    return render_template('home.html', user=user, questions=question_results)


@app.route('/register', methods=['GET', 'POST'])
def register():
    user = get_current_user()

    if user:
        return redirect(url_for('index'))

    if request.method == 'POST':
        db = get_db()

        existing_user_cur = db.execute(
            'SELECT id FROM users WHERE name = ?', [request.form['name']])
        existing_user = existing_user_cur.fetchone()

        if existing_user:
            error = 'User already exists!'
            return render_template('register.html', user=user, error=error)

        hashed_password = generate_password_hash(
            request.form['password'], method='sha256')  # make hash password

        # insert data from /register POST to user table in database and create a user
        db.execute('INSERT INTO users (name, password, expert, admin) VALUES (?, ?, ?, ?)', [
            request.form['name'], hashed_password, '0', '0'])
        db.commit()

        session['user'] = request.form['name']

        return redirect(url_for('index'))

    return render_template('register.html', user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    user = get_current_user()

    if user:
        return redirect(url_for('index'))

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
            error = 'Username or password Invalid!'
            return render_template('login.html', user=user, error=error)

    return render_template('login.html', user=user)


@app.route('/question/<question_id>')
def question(question_id):
    user = get_current_user()
    db = get_db()

    question_cur = db.execute(
        '''SELECT 
            questions.questions_text,
            questions.answer_text,
            askers.name as asker_name,
            experts.name as expert_name
        FROM questions
        JOIN users as askers ON askers.id = questions.asked_by_id
        JOIN users as experts ON experts.id = questions.expert_id
        WHERE questions.id = ?''', [question_id])
    question_result = question_cur.fetchone()

    return render_template('question.html', user=user, question=question_result)


@app.route('/answer/<question_id>', methods=['GET', 'POST'])
def answer(question_id):
    user = get_current_user()

    if not user:
        return redirect(url_for('login'))

    if user['expert'] == 0:
        return redirect(url_for('index'))

    db = get_db()

    if request.method == 'POST':
        # add answer to a question
        db.execute('UPDATE questions SET answer_text = ? WHERE id = ?', [
                   request.form['answer'], question_id])
        db.commit()

        return redirect(url_for('unanswered'))

    # get questions for an expert
    question_cur = db.execute(
        'SELECT id, questions_text FROM questions WHERE id = ?', [question_id])
    question_result = question_cur.fetchone()

    return render_template('answer.html', user=user, question=question_result)


@app.route('/ask', methods=['GET', 'POST'])
def ask():
    user = get_current_user()

    if not user:
        return redirect(url_for('login'))

    db = get_db()

    if request.method == 'POST':
        # add a question from a normal user for an specific expert
        db.execute('INSERT INTO questions(questions_text, asked_by_id, expert_id) VALUES (?, ?, ?)', [
                   request.form['question'], user['id'], request.form['expert']])
        db.commit()

        return redirect(url_for('index'))

    # get all expert for dropdown
    expert_cur = db.execute('SELECT id, name FROM users WHERE expert = 1')
    expert_results = expert_cur.fetchall()

    return render_template('ask.html', user=user, experts=expert_results)


@app.route('/unanswered')
def unanswered():
    user = get_current_user()

    if not user:
        return redirect(url_for('login'))

    if user['expert'] == 0:
        return redirect(url_for('index'))

    db = get_db()

    # get all question for an expert user
    question_cur = db.execute(
        '''SELECT questions.id, questions.questions_text, users.name
        FROM questions
        JOIN users ON questions.asked_by_id = users.id
        WHERE questions.answer_text IS null AND questions.expert_id = ?''', [user['id']])
    question_results = question_cur.fetchall()

    return render_template('unanswered.html', user=user, questions=question_results)


@ app.route('/users')
def users():
    user = get_current_user()

    if not user:
        return redirect(url_for('login'))

    if user['admin'] == 0:
        return redirect(url_for('index'))

    db = get_db()

    # get list of all the users
    users_cur = db.execute('SELECT id, name, expert, admin FROM users')
    users_results = users_cur.fetchall()

    return render_template('users.html', user=user, users=users_results)


@ app.route('/promote/<user_id>')
def promote(user_id):
    user = get_current_user()

    if not user:
        return redirect(url_for('login'))

    if user['admin'] == 0:
        return redirect(url_for('index'))

    db = get_db()

    # promote a user to expert
    db.execute('UPDATE users SET expert = 1 WHERE id = ?', [user_id])
    db.commit()

    return redirect(url_for('users'))


@ app.route('/logout')
def logout():
    # destroy session
    session.pop('user', None)

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
