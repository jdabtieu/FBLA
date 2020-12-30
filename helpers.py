import secrets
import re
from functools import wraps

from flask import redirect, request, session
from flask_mail import Message


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login?next=" + request.path)
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    Decorate routes to require admin login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login?next=" + request.path)
        if not session.get("admin"):
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function


def generate_password():
    """
    Generates a random 16-character password.

    used on Users page to manually reset passwords.
    """
    password = secrets.token_urlsafe(16)
    return password


def send_email(subject, sender, recipients, text, mail):
    message = Message(subject, sender=sender, recipients=recipients, body=text)
    mail.send(message)


def verify_text(text):
    """
    Check if text only contains A-Z, a-z, 0-9, underscores, and dashes
    """
    return bool(re.match(r'^[\w\-]+$', text))


def check_problem(qtype, ans, a, b, c, d):
    """
    Check if a problem contains all required fields based on the question type
    """
    # Multiple Choice & Dropdown should have all 4 choices
    if qtype == "MC" or qtype == "Drop":
        if not ans or not a or not b or not c or not d:
            return False
        return True

    # True/False should have two fields
    if qtype == "TF":
        if not ans or not a or not b:
            return False
        if not (ans == 'a' or ans == 'b'):
            return False
        return True

    # Fill in the Blank should have at least one accepted answer
    if qtype == "Blank":
        if not a:
            return False
        return True

    # Select All doesn't have any requirements
    if qtype == "Select":
        return True

    # Failsafe for any unrecognized problem types
    return False


def parse_quiz_answers(form):
    """
    Parses the answers from a quiz and returns them as an array of tuples
    """
    answers = []
    for item in form:
        list_answer = form.getlist(item)
        if len(list_answer) > 1:  # Dealing with multiple-select
            ans = ""
            for answer in list_answer:
                ans += answer.split("_")[1]
            answers.append((item, ans))
        else:  # Dealing with single-answer
            split = form.get(item).split("_")
            if item == "csrf_token":  # Ignore the CSRF token
                continue
            if "blank" in item:  # Dealing with fill in the blank
                answers.append((item.split("_")[0], form.get(item)))
            elif len(split) == 2:  # Dealing with select questions
                answers.append((item, split[1]))

    return answers
