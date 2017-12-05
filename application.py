from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_mail import Mail, Message
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, check_confirmed, lookup, usd
from itsdangerous import URLSafeTimedSerializer

# Configure application
app = Flask(__name__)

# Ensure responses aren't cached
if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


app.config.update(SECRET_KEY='CampusGuide',
                  SECURITY_PASSWORD_SALT='danielandbillogsquadup')

mail = Mail(app)

app.config.update(DEBUG=True,
                  # EMAIL SETTINGS
                  MAIL_SERVER='smtp.gmail.com',
                  MAIL_PORT=587,
                  MAIL_USE_SSL=False,
                  MAIL_USE_TLS=True,
                  MAIL_USERNAME='HarvardCampusGuide@gmail.com',
                  MAIL_PASSWORD='thisiscs50',
                  MAIL_DEFAULT_SENDER='HarvardCampusGuide@gmail.com')

mail = Mail(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///campusguide.db")

ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])


@app.route("/")
@login_required
@check_confirmed
def index():
    """Shows latest location ratings and generates random location"""
    return render_template("location.html")
    # # Pulls out latest 5 entries from ratings table
    # latest = db.execute("SELECT * FROM (SELECT * FROM ratings ORDER BY datetime DESC LIMIT 0,5) ORDER BY datetime DESC")

    # numLocations = db.execute("SELECT Count(*) FROM locations")

    # r_num = random.randint(0, 100)

    # r_location = db.execute("SELECT * FROM locations WHERE id = :r_num", r_num=r_num)

    # # renders index.html page with correctly formatted values
    # return render_template("index.html", latest=latest, r_location=r_location)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["status"] = db.execute(
            "SELECT confirmed FROM users WHERE id = :user_id", user_id=session["user_id"])[0]["confirmed"]

        if session["status"] == 0:
            return render_template("unconfirmed.html")
        else:
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username is not taken
        if len(rows) != 0:
            return apology("username taken", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmation password was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure email was submitted
        elif not request.form.get("email"):
            return apology("must provide email", 400)

        elif request.form.get("email")[-20:] != "@college.harvard.edu":
            return apology("please enter a valid @college.harvard.edu email")

        # Ensure password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation must match", 400)

        # Store valid username
        username = request.form.get("username")

        # Store valid password
        password = request.form.get("password")

        # Store valid email
        email = request.form.get("email")

        # Calculate and store hash from password
        p_hash = generate_password_hash(password)

        # Put username and password information into database
        result = db.execute("INSERT INTO users (username, hash, email) VALUES (:username, :p_hash, :email)",
                   username=username, p_hash=str(p_hash), email=email)

        session["user_id"] = result

        flash("Registered!")

        session["status"] = db.execute("SELECT confirmed FROM users WHERE id = :user_id",
                                            user_id=session["user_id"])[0]["confirmed"]

        subject = "Please confirm your Harvard CampusGuide email"

        token = ts.dumps(email, salt='danielandbillogsquadup')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template("email.html", confirm_url=confirm_url)

        send_email(email, subject, html)

        flash('A confirmation email has been sent via email.', 'success')

        return redirect("/unconfirmed")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
@check_confirmed
def change_password():
    """Change user password"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensures current password was provided
        if not request.form.get("current_password"):
            return apology("must provide current password", 400)

        # Ensures new password was provided
        if not request.form.get("new_password"):
            return apology("must provide new password", 400)

        # Ensures confirmation was provided
        if not request.form.get("confirmation"):
            return apology("must confirm new password", 400)

        rows = db.execute("SELECT * FROM users WHERE id = :user_id",
                          user_id=session["user_id"])

        # Ensures current password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("current_password")):
            return apology("invalid password", 400)

        # Ensures password and confirmation match
        elif request.form.get("new_password") != request.form.get("confirmation"):
            return apology("password and confirmation must match", 400)

        # Ensures new password is different
        if request.form.get("new_password") == request.form.get("current_password"):
            return apology("new password must be different", 400)

        # Stores new password
        password = request.form.get("new_password")

        # Generates hash for new password
        p_hash = generate_password_hash(password)

        # Puts new password information into database
        db.execute("UPDATE users SET hash = :p_hash WHERE id = :user_id",
                   p_hash=str(p_hash), user_id=session["user_id"])

        # Logs user out
        session.clear()

        # Notifies successful password update
        flash("Password updated! Please log in again.")

        # Redirects user to log in again
        return render_template("login.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change_password.html")


@app.route("/unconfirmed")
@login_required
def unconfirmed():
    if session["status"] == 1:
        return redirect("/")
    else:
        flash('Please confirm your account!', 'warning')
        return render_template("unconfirmed.html")


@app.route("/confirm/<token>")
@login_required
def confirm_email(token):
    user_id = session["user_id"]
    try:
        email = ts.loads(token, salt='danielandbillogsquadup', max_age=86400)
    except:
        return apology("Confirmation link too old!")

    status = db.execute("SELECT confirmed FROM users WHERE id = :user_id",
                        user_id=user_id)[0]["confirmed"]
    if status == 1:
        flash('Account already confirmed. Please log in.', 'success')
    else:
        db.execute("UPDATE users SET confirmed = 1 WHERE id = :user_id",
                   user_id=user_id)
        session["status"] = 1
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect('/')


@app.route("/rate", methods=["GET", "POST"])
@login_required
def rate():
    if request.method == "POST":
        print("iubfiuwbfiuwbiufbwiubfiuwbeifbwiebfiuwbfiubwiuefbiwbfwuebfiuwebifu")
        mood = request.form.get("mood")
        print("iubfiuwbfiuwbiufbwiubfiuwbeifbwiebfiuwbfiubwiuefbiwbfwuebfiuwebifu")
        print(mood)
        if not mood:
            return apology("please answer every question")
        if mood == 'happy':
            mood = 1
        elif mood == 'neutral':
            mood = 2
        elif mood == "unhappy":
            mood = 3
        elif mood == "sad":
            mood = 4
        else:
            mood = 5
        db.execute("INSERT INTO ratings (user_id, location_id, mood) VALUES (:user_id, :location_id, :mood)", user_id = session["user_id"], location_id = 11, mood = mood)
        return redirect("")
    if request.method == "GET":
        return render_template("rate.html")


#@app.route("/search")
    #query = request.args.get("q") + '%'


@app.route('/resend')
@login_required
def resend_confirmation():
    # Resends email

    # Gets email
    email = db.execute("SELECT email FROM users WHERE id = :user_id",
                       user_id=session["user_id"])[0]["email"]

    # Subject
    subject = "Harvard Campus Guide Confirmation"

    # Unique token
    token = ts.dumps(email, salt='danielandbillogsquadup')
    # Creates url
    confirm_url = url_for('confirm_email', token=token, _external=True)
    # Html formatting
    html = render_template("email.html", confirm_url=confirm_url)

    # Sends email
    send_email(email, subject, html)

    # Alerts email sent
    flash('A new confirmation email has been sent!', 'success')

    # Redirects to unconfirmed page
    return redirect("/unconfirmed")


def send_email(recipient, subject, html):
    msg = Message(subject,
                  recipients=[recipient],
                  html=html)
    mail.send(msg)


@app.route("/contact-us",methods=["GET","POST"])
def contact():

    name = request.form.get("name")
    suggestion = request.form.get("suggestion")
    picture = request.form.get("picture")

    if request.method == "POST":
        if suggestion == None or len(suggestion) == 0:
            flash("I'm sorry, there was a mistake processing your suggestion!")
            return render_template("/contact.html")
        else:
            if not session["user_id"]:
                db.execute("INSERT INTO suggestions (name, suggestion, picture) VALUES (:name, :suggestion, :picture)", suggestion = suggestion, name = name, picture = picture)
            else:
                db.execute("INSERT INTO suggestions (user_id, name, suggestion, picture) VALUES (:user_id, :name, :suggestion, :picture)", user_id = session["user_id"], name = name, suggestion = suggestion, picture = picture)
            flash("Submitted suggestion!")
            return redirect("/")

    if request.method == "GET":
        return render_template("contact.html")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
