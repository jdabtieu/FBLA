import os
import sys
import logging
from datetime import datetime, timedelta

import jwt
from cs50 import SQL
from flask import (Flask, flash, redirect, render_template, request,
                   send_from_directory, session, abort)
from flask_mail import Mail
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from google_auth_oauthlib.flow import Flow
import requests
from werkzeug.exceptions import HTTPException, InternalServerError, default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import *

app = Flask(__name__)
app.config.from_object('settings')

# Configure logging
logging.basicConfig(
    filename=app.config['LOGGING_FILE_LOCATION'],
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s',
)
logging.getLogger().addHandler(logging.StreamHandler())

# Configure flask-session
Session(app)

# Configure cs50
db = SQL("sqlite:///database.db")

# Configure flask-mail
mail = Mail(app)

# Configure flask-WTF
csrf = CSRFProtect(app)
csrf.init_app(app)


# Ensure that during maintenance mode, non-admins cannot access the site
@app.before_request
def check_for_maintenance():
    # Don't prevent login or getting assets
    if request.path == '/login' or (request.path[0:8] == '/assets/' and
                                    '..' not in request.path):
        return

    maintenance_mode = bool(os.path.exists('maintenance_mode'))
    if maintenance_mode:
        # Prevent Internal Server error if session only contains CSRF token
        if not session or 'admin' not in session:
            return render_template("error/maintenance.html"), 503
        elif not session['admin']:
            return render_template("error/maintenance.html"), 503
        else:
            flash("Maintenance mode is enabled", "warning")


@app.route("/")
def index():
    # User not logged in
    if not session or "user_id" not in session:
        return render_template("index.html")

    # Get problem data for user
    most_difficult = db.execute(
        ('SELECT category, submissions_data.correct, COUNT(*) FROM submissions_data '
         'LEFT JOIN problems ON submissions_data.problem_id=problems.id WHERE sub_id IN '
         '(SELECT id FROM submissions WHERE user_id=?) GROUP BY '
         'category, submissions_data.correct '
         'ORDER BY category DESC, submissions_data.correct DESC'), session["user_id"])

    # Find most difficult problem type of user
    lowest_score = 2
    lowest_category = ""
    for i in range(0, len(most_difficult) // 2):
        corr = most_difficult[i * 2]
        incc = most_difficult[i * 2 + 1]
        try:
            score = corr['COUNT(*)'] / (incc['COUNT(*)'] + corr['COUNT(*)'])
        except ZeroDivisionError:
            score = 9
        if score < lowest_score:
            lowest_score = score
            lowest_category = corr['category']

    return render_template("logged-in.html", most_difficult=lowest_category)


@app.route("/assets/<path:filename>")
def get_asset(filename):
    return send_from_directory("assets/", filename)


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/help")
def help():
    return render_template("help.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget user id
    session.clear()

    if request.method == "GET":
        return render_template("auth/login.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"])

    # Reached using POST

    username = request.form.get("username")
    password = request.form.get("password")

    # Ensure username and password were submitted
    if not username or not password:
        flash('Username and password cannot be blank', 'danger')
        return render_template("auth/login.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"]), 400

    # Ensure username exists and password is correct
    rows = db.execute("SELECT * FROM users WHERE username = :username",
                      username=request.form.get("username"))
    if len(rows) != 1 or not check_password_hash(rows[0]["password"], password):
        flash('Incorrect username/password', 'danger')
        return render_template("auth/login.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"]), 401

    # Ensure user is not banned and has confirmed their account
    if rows[0]["banned"]:
        flash('You are banned! Please message an admin to appeal the ban', 'danger')
        return render_template("auth/login.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"]), 403
    if not rows[0]["verified"]:
        flash('Your account has not been confirmed. Please check your email', 'danger')
        return render_template("auth/login.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"]), 403

    # 2fa verification via email
    if rows[0]["twofa"]:
        exp = datetime.utcnow() + timedelta(seconds=1800)
        email = rows[0]["email"]
        token = jwt.encode(
            {
                'email': email,
                'expiration': exp.isoformat()
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        text = render_template('email/confirm_login_text.txt',
                               username=username, token=token)

        send_email('Confirm Your FBLAquiz Login',
                   app.config['MAIL_DEFAULT_SENDER'], [email], text, mail)

        flash(('A login confirmation email has been sent to the email address you '
               'provided. Be sure to check your spam folder!'), 'success')
        return render_template("auth/login.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"])

    # Remember which user has logged in
    session["user_id"] = rows[0]["id"]
    session["username"] = rows[0]["username"]
    session["admin"] = rows[0]["admin"]

    # Redirect user to next page
    next_url = request.form.get("next")
    if next_url and '//' not in next_url and ':' not in next_url:
        return redirect(next_url)
    return redirect('/')


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/login/google")
def login_google():
    if not app.config["USE_GOOGLE_LOGIN"]:
        return abort(404)

    # Get required scopes
    SCOPES = ["https://www.googleapis.com/auth/userinfo.email",
              "https://www.googleapis.com/auth/userinfo.profile",
              "openid"]
    flow = Flow.from_client_secrets_file(
        "credentials.json", scopes=SCOPES,
        redirect_uri=app.config["WEBSERVER_URL"] + "/login/callback")
    # Redirect user to authorization URL
    auth_url, _ = flow.authorization_url(prompt='consent')
    return redirect(auth_url)


@app.route("/login/callback")
def login_callback():
    if not app.config["USE_GOOGLE_LOGIN"]:
        return abort(404)

    # Fetch name and email from Google
    code = request.args.get("code")
    SCOPES = ["https://www.googleapis.com/auth/userinfo.email",
              "https://www.googleapis.com/auth/userinfo.profile",
              "openid"]
    flow = Flow.from_client_secrets_file(
        "credentials.json", scopes=SCOPES,
        redirect_uri=app.config["WEBSERVER_URL"] + "/login/callback")
    flow.fetch_token(code=code)
    creds = flow.credentials
    userinfo = requests.get(("https://www.googleapis.com/oauth2/v3/userinfo?"
                             "alt=json&access_token=") + creds.token).json()

    # Check if user is registering an account
    rows = db.execute("SELECT * FROM users WHERE email=?", userinfo["email"])
    if len(rows) == 0:
        db.execute(("INSERT INTO users (username, password, email, join_date, verified) "
                    "VALUES (?, ?, ?, datetime('now'), 1)"),
                   userinfo["name"], creds.to_json(), userinfo["email"])
        rows = db.execute("SELECT * FROM users WHERE email=?", userinfo["email"])

    # Remember which user has logged in
    session["user_id"] = rows[0]["id"]
    session["username"] = rows[0]["username"]
    session["admin"] = rows[0]["admin"]
    return redirect("/")



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("auth/register.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"])

    # Reached using POST

    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    email = request.form.get("email")

    # Ensure username is valid
    if not username:
        flash('Username cannot be blank', 'danger')
        return render_template("auth/register.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"]), 400
    if not verify_text(username):
        flash('Invalid username', 'danger')
        return render_template("auth/register.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"]), 400

    # Ensure password is valid
    if not password or len(password) < 8:
        flash('Password must be at least 8 characters', 'danger')
        return render_template("auth/register.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"]), 400
    if not confirmation or password != confirmation:
        flash('Passwords do not match', 'danger')
        return render_template("auth/register.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"]), 400

    # Ensure username and email do not already exist
    rows = db.execute("SELECT * FROM users WHERE username=:username",
                      username=username)
    if len(rows) > 0:
        flash('Username already exists', 'danger')
        return render_template("auth/register.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"]), 409
    rows = db.execute("SELECT * FROM users WHERE email=:email",
                      email=request.form.get("email"))
    if len(rows) > 0:
        flash('Email already exists', 'danger')
        return render_template("auth/register.html",
                               use_google=app.config["USE_GOOGLE_LOGIN"]), 409

    # Send confirmation email
    exp = datetime.utcnow() + timedelta(seconds=1800)
    token = jwt.encode(
        {
            'email': email,
            'expiration': exp.isoformat()
        },
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    text = render_template('email/confirm_account_text.txt',
                           username=username, token=token)

    send_email('Confirm Your FBLAquiz Account',
               app.config['MAIL_DEFAULT_SENDER'], [email], text, mail)

    db.execute(("INSERT INTO users(username, password, email, join_date) "
                "VALUES(:username, :password, :email, datetime('now'))"),
               username=username,
               password=generate_password_hash(password),
               email=email)

    flash(("An account creation confirmation email has been sent to the email address "
           "you provided. Be sure to check your spam folder!"), 'success')
    return render_template("auth/register.html",
                           use_google=app.config["USE_GOOGLE_LOGIN"])


@app.route('/confirmregister/<token>')
def confirm_register(token):
    # Decode token
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        sys.stderr.write(str(e))
        token = 0

    if not token:
        flash("Email verification link invalid", "danger")
        return redirect("/register")
    if datetime.strptime(token["expiration"], "%Y-%m-%dT%H:%M:%S.%f") < datetime.utcnow():
        db.execute(
            "DELETE FROM users WHERE verified=0 and email=:email", email=token['email'])
        flash("Email verification link expired. Please register again", "danger")
        return redirect("/register")

    db.execute("UPDATE users SET verified=1 WHERE email=:email", email=token['email'])

    # Log user in
    user = db.execute(
        "SELECT * FROM users WHERE email=:email", email=token['email'])[0]
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["admin"] = False  # Ensure no one can get admin right after registering

    return redirect("/")


@app.route('/confirmlogin/<token>')
def confirm_login(token):
    # Decode token
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        sys.stderr.write(str(e))
        token = 0

    if not token:
        flash('Invalid login verification link', 'danger')
        return render_template("auth/login.html"), 400
    if datetime.strptime(token["expiration"], "%Y-%m-%dT%H:%M:%S.%f") < datetime.utcnow():
        flash('Login verification link expired; Please re-login', 'danger')
        return render_template("auth/login.html"), 401

    # Log user in
    user = db.execute(
        "SELECT * FROM users WHERE email=:email", email=token['email'])[0]
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["admin"] = user["admin"]

    return redirect("/")


@app.route("/profile")
@login_required
def settings():
    user_data = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])
    total_quizzes = len(db.execute(
        "SELECT * FROM submissions WHERE user_id=?", session["user_id"]))
    if total_quizzes == 0:
        recent_quiz = None
        perfects = 0
    else:
        recent_quiz = db.execute(
            "SELECT * FROM submissions WHERE user_id=? ORDER BY date DESC LIMIT 1",
            session["user_id"])[0]
        perfects = len(db.execute(
            "SELECT * FROM submissions WHERE user_id=? AND score=5", session["user_id"]))

    return render_template("profile.html", user_data=user_data[0],
                           recent_quiz=recent_quiz, perfects=perfects,
                           total_quizzes=total_quizzes)


@app.route("/settings/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    if request.method == "GET":
        return render_template("auth/changepassword.html")

    # Reached using POST

    old_password = request.form.get("password")
    new_password = request.form.get("newPassword")
    confirmation = request.form.get("confirmation")

    # Ensure passwords were submitted and they match
    if not old_password:
        flash('Password cannot be blank', 'danger')
        return render_template("auth/changepassword.html"), 400
    if not new_password or len(new_password) < 8:
        flash('New password must be at least 8 characters', 'danger')
        return render_template("auth/changepassword.html"), 400
    if not confirmation or new_password != confirmation:
        flash('Passwords do not match', 'danger')
        return render_template("auth/changepassword.html"), 400

    # Ensure username exists and password is correct
    rows = db.execute("SELECT * FROM users WHERE id=:id",
                      id=session["user_id"])
    if len(rows) != 1 or not check_password_hash(rows[0]["password"], old_password):
        flash('Incorrect password', 'danger')
        return render_template("auth/changepassword.html"), 401

    db.execute("UPDATE users SET password=:new WHERE id=:id",
               new=generate_password_hash(new_password),
               id=session["user_id"])

    flash("Password change successful", "success")
    return redirect("/profile")


@app.route("/settings/toggle2fa", methods=["GET", "POST"])
@login_required
def toggle2fa():
    user = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])[0]

    if request.method == "GET":
        return render_template("auth/2fa_confirm.html", enabled=user["twofa"])

    # Reached via POST

    password = request.form.get("password")

    if not password or not check_password_hash(user['password'], password):
        flash('Incorrect password', 'danger')
        return render_template("auth/2fa_confirm.html", enabled=user["twofa"]), 401

    if user["twofa"]:
        db.execute("UPDATE users SET twofa=0 WHERE id=:id", id=session["user_id"])
        flash("2FA successfully disabled", "success")
    else:
        db.execute("UPDATE users SET twofa=1 WHERE id=:id", id=session["user_id"])
        flash("2FA successfully enabled", "success")
    return redirect("/profile")


@app.route("/forgotpassword", methods=["GET", "POST"])
def forgotpassword():
    session.clear()

    if request.method == "GET":
        return render_template("auth/forgotpassword.html")

    # Reached via POST

    email = request.form.get("email")

    # Ensure email was submitted
    if not email:
        flash('Email cannot be blank', 'danger')
        return render_template("auth/forgotpassword.html"), 400

    rows = db.execute("SELECT * FROM users WHERE email=:email",
                      email=request.form.get("email"))
    if len(rows) == 1:
        exp = datetime.utcnow() + timedelta(seconds=1800)
        token = jwt.encode(
            {
                'user_id': rows[0]["id"],
                'expiration': exp.isoformat()
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        text = render_template('email/reset_password_text.txt',
                               username=rows[0]["username"], token=token)

        send_email('Reset Your FBLAquiz Password',
                   app.config['MAIL_DEFAULT_SENDER'], [email], text, mail)

    flash(("If there is an account associated with that email, a password reset email "
           "has been sent"), 'success')
    return render_template("auth/forgotpassword.html")


@app.route('/resetpassword/<token>', methods=['GET', 'POST'])
def reset_password_user(token):
    # Decode token
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = token['user_id']
    except Exception as e:
        sys.stderr.write(str(e))
        user_id = 0

    if not user_id or datetime.strptime(
            token["expiration"], "%Y-%m-%dT%H:%M:%S.%f") < datetime.utcnow():
        flash('Password reset link expired/invalid', 'danger')
        return redirect('/forgotpassword')

    if request.method == "GET":
        return render_template('auth/resetpassword.html')

    # Reached via POST

    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    # Ensure passwords match and are valid
    if not password or len(password) < 8:
        flash('New password must be at least 8 characters', 'danger')
        return render_template("auth/resetpassword.html"), 400
    if not confirmation or password != confirmation:
        flash('Passwords do not match', 'danger')
        return render_template("auth/resetpassword.html"), 400

    db.execute("UPDATE users SET password=:new WHERE id=:id",
               new=generate_password_hash(password), id=user_id)

    flash('Your password has been successfully reset', 'success')
    return redirect("/login")


@app.route('/problems')
@admin_required
def problems():
    data = db.execute(
        "SELECT category, COUNT(*) FROM problems WHERE deleted=0 GROUP BY category")

    # Prepare warnings for categories with less than 5 problems
    non_length = []
    for item in data:
        if item['COUNT(*)'] < 5:
            non_length.append(item['category'])

    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    length = len(db.execute("SELECT * FROM problems WHERE draft=0 AND deleted=0"))
    data = db.execute(("SELECT * FROM problems WHERE draft=0 AND deleted=0 "
                       "ORDER BY id ASC LIMIT 50 OFFSET ?"), page)

    return render_template('problem/problems.html', data=data, length=-(-length // 50),
                           non_length=non_length)


@app.route('/problems/draft')
@admin_required
def draft_problems():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    length = len(db.execute("SELECT * FROM problems WHERE draft=1"))
    data = db.execute(("SELECT * FROM problems WHERE draft=1 ORDER BY id ASC LIMIT 50 "
                       "OFFSET ?"), page)

    return render_template('problem/draft_problems.html',
                           data=data, length=-(-length // 50))


@app.route('/problem/<problem_id>')
@admin_required
def problem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:pid",
                      pid=problem_id)

    # Ensure problem exists
    if len(data) != 1:
        return render_template("problem/problem_noexist.html"), 404

    # Get problem statistics
    raw_sub_data = db.execute("SELECT * FROM submissions_data WHERE problem_id=?",
                              problem_id)

    sub_data = dict()

    correct_subs = 0
    for item in raw_sub_data:
        correct_subs += 1 if item['correct'] else 0

    if len(raw_sub_data) == 0:
        sub_data['percentage'] = 'No submissions yet'
        sub_data['total_subs'] = 'No submissions yet'
        sub_data['correct_subs'] = 'No submissions yet'
    else:
        sub_data['percentage'] = "{0:.2f}%".format(correct_subs / len(raw_sub_data) * 100)
        sub_data['total_subs'] = str(len(raw_sub_data))
        sub_data['correct_subs'] = str(correct_subs)

    if request.method == "GET":
        return render_template('problem/problem.html', data=data[0], sub_data=sub_data)


@app.route('/problem/<problem_id>/publish', methods=["POST"])
@admin_required
def publish_problem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:pid",
                      pid=problem_id)

    # Ensure problem exists
    if len(data) != 1:
        return render_template("problem/problem_noexist.html"), 404

    db.execute("UPDATE problems SET draft=0 WHERE id=:pid", pid=problem_id)

    flash('Problem successfully published', 'success')
    return redirect("/problem/" + problem_id)


@app.route('/problem/<problem_id>/edit', methods=["GET", "POST"])
@admin_required
def editproblem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    if request.method == "GET":
        return render_template('problem/editproblem.html', data=data[0])

    # Reached via POST

    # Get inputs & validate based on question type
    qtype = data[0]["type"]

    question = request.form.get("question")
    difficulty = request.form.get("difficulty")
    category = request.form.get("category")

    if not question or not difficulty or not category:
        flash("You did not fill all required fields", "danger")
        return render_template("problem/editproblem.html", data=data[0]), 400

    ans = request.form.get("ans")
    a = request.form.get("a")
    b = request.form.get("b")
    c = request.form.get("c")
    d = request.form.get("d")

    if not check_problem(qtype, ans, a, b, c, d):
        flash("You did not fill all required fields", "danger")
        return render_template("problem/editproblem.html", data=data[0]), 400

    # Extra steps for storage of different question types
    if qtype == "TF":
        db.execute(("UPDATE problems SET description=?, a=?, b=?, correct=?, "
                    "category=?, difficulty=? WHERE id=?"),
                   question, a, b, ans, category, difficulty, problem_id)
        flash('Problem successfully edited', 'success')
        return redirect("/problem/" + problem_id)
    elif qtype == "Blank":
        ans = ""
    elif qtype == "Select":
        all_ans = request.form.getlist("ans")
        ans = ""
        for letter in all_ans:
            ans += letter

    db.execute(("UPDATE problems SET description=?, a=?, b=?, c=?, d=?, correct=?, "
                "category=?, difficulty=? WHERE id=?"),
               question, a, b, c, d, ans, category, difficulty, problem_id)

    flash('Problem successfully edited', 'success')
    return redirect("/problem/" + problem_id)


@app.route('/problem/<problem_id>/delete', methods=["POST"])
@admin_required
def delete_problem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    db.execute("UPDATE problems SET deleted=1 WHERE id=:pid", pid=problem_id)

    flash('Problem successfully deleted', 'success')
    return redirect("/problems")


@app.route("/admin/console")
@admin_required
def admin_console():
    return render_template("admin/console.html",
                           maintenance_mode=os.path.exists('maintenance_mode'))


@csrf.exempt
@app.route("/admin/submissions")
@admin_required
def admin_submissions():
    # Parse & prepare filters
    modifier = "WHERE"
    args = []
    if request.args.get("username"):
        # None usernames means anonymous users
        if request.args.get("username") == "None":
            modifier += " username IS NULL AND"
        else:
            modifier += " username=? AND"
            args.append(request.args.get("username"))

    if request.args.get("score"):
        modifier += " score=? AND"
        args.append(request.args.get("score"))

    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50
    modifier += " 1=1"

    # Query database for submissions and get number of submissions for pagination
    length = len(db.execute(("SELECT submissions.*, users.username FROM submissions "
                             "LEFT JOIN users ON user_id=users.id ") + modifier, *args))

    args.append(page)
    submissions = db.execute(("SELECT submissions.*, users.username FROM submissions "
                              f"LEFT JOIN users ON user_id=users.id {modifier}"
                              " LIMIT 50 OFFSET ?"), *args)

    return render_template("admin/submissions.html",
                           data=submissions, length=-(-length // 50))


@app.route("/admin/users")
@admin_required
def admin_users():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    count = len(db.execute("SELECT * FROM users"))
    data = db.execute("SELECT * FROM users LIMIT 50 OFFSET ?", page)
    return render_template("admin/users.html", data=data, length=-(-count // 50))


@app.route("/admin/createproblem", methods=["GET", "POST"])
@admin_required
def createproblem():
    if request.method == "GET":
        return render_template("problem/create.html")

    # Reached via POST

    # Get inputs & validate them
    qtype = request.form.get("type")

    if not qtype or qtype not in ['MC', 'TF', 'Drop', 'Blank', 'Select']:
        flash("You did not fill all required fields", "danger")
        return render_template("problem/create.html"), 400

    question = request.form.get("question")
    difficulty = request.form.get("difficulty")
    category = request.form.get("category")
    draft = 1 if request.form.get("draft") else 0

    if not question or not difficulty or not category:
        flash("You did not fill all required fields", "danger")
        return render_template("problem/create.html"), 400

    ans = request.form.get("ans")
    a = request.form.get("a")
    b = request.form.get("b")
    c = request.form.get("c")
    d = request.form.get("d")

    if not check_problem(qtype, ans, a, b, c, d):
        flash("You did not fill all required fields", "danger")
        return render_template("problem/create.html"), 400

    if qtype == "TF":
        db.execute(("INSERT INTO problems (type, description, a, b, correct, category, "
                    "difficulty, draft) VALUES(?, ?, ?, ?, ?, ?, ?, ?)"),
                   qtype, question, a, b, ans, category, difficulty, draft)

        problem_id = db.execute(
            "SELECT * FROM problems ORDER BY id DESC LIMIT 1")[0]["id"]

        flash('Problem successfully created', 'success')
        return redirect("/problem/" + str(problem_id))
    elif qtype == "Blank":
        ans = ""

    elif qtype == "Select":
        all_ans = request.form.getlist("ans")
        ans = ""
        for letter in all_ans:
            ans += letter

    db.execute(("INSERT INTO problems (type, description, a, b, c, d, correct, category, "
                "difficulty, draft) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
               qtype, question, a, b, c, d, ans, category, difficulty, draft)

    problem_id = db.execute("SELECT * FROM problems ORDER BY id DESC LIMIT 1")[0]["id"]

    flash('Problem successfully created', 'success')
    return redirect("/problem/" + str(problem_id))


@app.route("/admin/ban", methods=["POST"])
@admin_required
def ban():
    # Ensure user exists
    user_id = request.form.get("user_id")
    if not user_id:
        flash("Must provide user ID", "danger")
        return redirect("/admin/users")

    user = db.execute("SELECT * FROM users WHERE id=:id", id=user_id)

    if len(user) == 0:
        flash("That user doesn't exist", "danger")
        return redirect("/admin/users")

    user_id = int(user_id)
    user = user[0]

    # Ensure users can't ban themselves or other admins
    if user_id == session["user_id"]:
        flash("Cannot ban yourself", "danger")
        return redirect("/admin/users")

    if user["admin"] and session["user_id"] != 1:
        flash("Only the super-admin can ban admins", "danger")
        return redirect("/admin/users")

    db.execute("UPDATE users SET banned=:status WHERE id=:id",
               status=not user["banned"], id=user_id)

    if user["banned"]:
        flash("Successfully unbanned " + user["username"], "success")
    else:
        flash("Successfully banned " + user["username"], "success")

    return redirect("/admin/users")


@app.route("/admin/resetpass", methods=["POST"])
@admin_required
def reset_password():
    # Ensure user exists
    user_id = request.form.get("user_id")
    if not user_id:
        flash("Must provide user ID", "danger")
        return redirect("/admin/users")

    user = db.execute("SELECT * FROM users WHERE id=:id", id=user_id)

    if len(user) == 0:
        flash("That user doesn't exist", "danger")
        return redirect("/admin/users")

    # Generate new password
    password = generate_password()
    db.execute("UPDATE users SET password=:p WHERE id=:id",
               p=generate_password_hash(password), id=user_id)

    flash("Password for " + user[0]["username"] +
          " resetted! Their new password is " + password, "success")
    return redirect("/admin/users")


@app.route("/admin/makeadmin", methods=["POST"])
@admin_required
def makeadmin():
    # Ensure user exists
    user_id = request.form.get("user_id")
    if not user_id:
        flash("Must provide user ID", "danger")
        return redirect("/admin/users")

    user = db.execute("SELECT * FROM users WHERE id=:id", id=user_id)

    if len(user) == 0:
        flash("That user doesn't exist", "danger")
        return redirect("/admin/users")

    user_id = int(user_id)
    admin_status = user[0]["admin"]

    # Prevent admins from revoking admin status (except super-admin)
    if admin_status and session["user_id"] != 1:
        flash("Only the super-admin can revoke admin status", "danger")
        return redirect("/admin/users")

    if admin_status and user_id == 1:
        flash("Cannot revoke super-admin privileges", "danger")
        return redirect("/admin/users")

    if admin_status and session["user_id"] == 1:
        db.execute("UPDATE users SET admin=0 WHERE id=:id", id=user_id)
        flash("Admin privileges for " + user[0]["username"] + " revoked", "success")
        return redirect("/admin/users")
    else:
        db.execute("UPDATE users SET admin=1 WHERE id=:id", id=user_id)
        flash("Admin privileges for " + user[0]["username"] + " granted", "success")
        return redirect("/admin/users")


@app.route("/admin/maintenance", methods=["POST"])
@admin_required
def maintenance():
    # Checks if the maintenance_mode file exists
    maintenance_mode = os.path.exists('maintenance_mode')

    if maintenance_mode:
        os.remove('maintenance_mode')
        flash("Disabled maintenance mode", "success")
    else:
        open('maintenance_mode', 'w').close()
        flash("Enabled maintenance mode", "success")

    return redirect('/admin/console')


@app.route("/quiz", methods=["GET", "POST"])
def quiz():
    if request.method == "GET":
        ptype = request.args.get('type')
        if ptype:
            return render_template('quizselect.html', ptype=ptype)
        return render_template("quizselect.html")

    # Reached via POST

    ptype = request.form.get("ptype")

    if ptype:
        questions = db.execute(("SELECT * FROM problems WHERE draft=0 AND deleted=0 "
                                "AND category=? ORDER BY RANDOM() LIMIT 5"), ptype)

        # Ensure the category exists and has at least 5 questions, else generate random
        if len(questions) >= 5:
            return render_template("quiz.html", questions=questions)

    questions = db.execute(("SELECT * FROM problems WHERE draft=0 AND deleted=0 "
                            "ORDER BY RANDOM() LIMIT 5"))

    return render_template("quiz.html", questions=questions)


@app.route("/quiz/results")
def quiz_results():
    sub_id = request.args.get("id")
    if not sub_id:
        flash("Missing quiz ID", "danger")
        return redirect("/quiz")

    # Get details about the submission to display to the user
    sub = db.execute(("SELECT submissions.*, users.username FROM submissions "
                      "LEFT JOIN users ON user_id=users.id WHERE submissions.id=:id"),
                     id=sub_id)

    if len(sub) == 0:
        flash("This submission doesn't exist", "danger")
        return redirect("/quiz")

    sub_data = db.execute(("SELECT * FROM submissions_data JOIN problems ON "
                           "problem_id=problems.id WHERE sub_id=:id"), id=sub_id)

    # Generate encouraging message
    score = sub[0]["score"]
    msg = ["You can do better than this!",
           "Try again for a better score!",
           "Try again to get perfect!",
           "Not bad, try again for a perfect score!",
           "So close! Try again for a chance of perfect!",
           "Wonderful job! Congratulations on a perfect score!"][score]

    return render_template("quizresults.html", sub=sub[0], sub_data=sub_data, msg=msg)


@app.route("/quiz/submit", methods=["POST"])
def quiz_submit():
    answers = parse_quiz_answers(request.form)
    correct = 0

    # Create blank submission & get unique ID
    db.execute("INSERT INTO submissions (score, date) VALUES(0, datetime('now'))")
    subid = db.execute("SELECT id FROM submissions ORDER BY id DESC LIMIT 1")[0]["id"]

    # Update user ID if logged in
    if session and "user_id" in session:
        db.execute("UPDATE submissions SET user_id=? WHERE id=?",
                   session["user_id"], subid)

    # Check answers
    for answer in answers:
        this_correct = False
        user_ans = answer[1]
        data = db.execute("SELECT * FROM problems WHERE id=?", answer[0])
        # Ensure user has not injected a fake problem
        if len(data) == 0:
            flash("Do not modify the quiz!", "danger")
            return redirect("/quiz")

        # Check answers based on problem types
        if (data[0]["type"] == "MC" or
                data[0]["type"] == "Drop" or
                data[0]["type"] == "TF"):
            this_correct = (data[0]["correct"] == user_ans)

        elif data[0]["type"] == "Blank":
            accepts = []
            for letter in "abcd":
                if data[0][letter]:
                    accepts.append(data[0][letter])
            this_correct = (user_ans in accepts)

        elif data[0]["type"] == "Select":
            user_ans = answer[1][:-1]  # Remove anti-blank token
            this_correct = (data[0]["correct"] == user_ans)

        # Insert this problem into submissions data
        if this_correct:
            correct += 1
        db.execute("INSERT INTO submissions_data VALUES(?, ?, ?, ?)",
                   subid, data[0]["id"], user_ans, int(this_correct))

    # Update score of submission
    db.execute("UPDATE submissions SET score=? WHERE id=?", correct, subid)

    return redirect("/quiz/results?id=" + str(subid))


@csrf.exempt
@app.route("/submissions")
@login_required
def user_submissions():
    modifier = ""
    args = []

    if request.args.get("score"):
        modifier += " AND score=?"
        args.insert(len(args), request.args.get("score"))

    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50
    args.insert(0, session["user_id"])

    # Query database for submissions and get number of submissions for pagination
    length = len(db.execute(
        "SELECT * FROM submissions WHERE user_id=?" + modifier, *args))
    args.append(page)
    submissions = db.execute("SELECT * FROM submissions WHERE user_id=?" + modifier +
                             " LIMIT 50 OFFSET ?", *args)

    return render_template("submissions.html", data=submissions, length=-(-length // 50))


# Error handling
def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    if e.code == 404:
        return render_template("error/404.html"), 404
    if e.code == 500:
        return render_template("error/500.html"), 500
    return render_template("error/generic.html", e=e), e.code


for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


# HTTP 418 error easter egg
@app.route("/teapot")
def teapot():
    return render_template("error/418.html"), 418


# Security headers
@app.after_request
def security_policies(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


# Allow running application.py when debugging
if __name__ == "__main__":
    app.run(debug=True, port=5000)
