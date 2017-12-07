from cs50 import SQL
import csv
import urllib.request
from flask import flash

from flask import redirect, render_template, request, session, flash
from functools import wraps

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///campusguide.db")


def apology(message, code=400):
    """Renders message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            flash("You must be logged in to view this. Sorry!")
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function


def check_confirmed(f):
    """Checks to see if user has confirmed email."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if db.execute("SELECT confirmed FROM users WHERE :user_id", user_id = session.get("user_id"))[0]['confirmed'] == 0:
            flash("Please confirm your account!", "warning")
            return redirect("/unconfirmed")
        return f(*args, **kwargs)
    return decorated_function
