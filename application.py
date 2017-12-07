import math
import datetime
from operator import itemgetter, attrgetter, methodcaller
from statistics import mode
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for, jsonify
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

g_location_id = 15

@app.route("/", methods=["GET", "POST"])
def index():
    """Shows latest location ratings and generates random location"""

    global g_location_id

    if request.method == "POST":

        mood = request.form.get("mood")
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

        # dont need to error check because something will always be input
        frequency = request.form.get("frequency")
        busy = request.form.get("busy")
        conducive = request.form.get("conducive")
        lit = request.form.get("lit")
        deviance = request.form.get("deviance")
        romance = request.form.get("romance")

        if session.get("user_id") is None:
            user_id = 0
        else:
            user_id = session["user_id"]

        db.execute("INSERT INTO ratings (user_id, location_id, mood, frequency, popularity, conducivity, litness, deviance, love) VALUES (:user_id, :location_id, :mood, :frequency, :busy, :conducive, :lit, :deviance, :romance)",
                    user_id = user_id, location_id = g_location_id, mood = mood, frequency = frequency, busy = busy, conducive = conducive, lit = lit, deviance = deviance, romance = romance)

        updateRatings(g_location_id)

        flash("Thank you for rating!")

        return redirect("/")

    else:

        locations = db.execute("SELECT * FROM locations WHERE description IS NOT NULL ORDER BY RANDOM() LIMIT 1")

        rand_location = locations[0]

        g_location_id = rand_location["id"]

        dining_info = db.execute("SELECT * FROM tags INNER JOIN locations ON tags.location_id = locations.id AND tags.label_id = 3")

        for location in dining_info:
            location["misc"] = float("{0:.3f}".format(diningRate(location)))

        dining_info = sorted(dining_info, key=itemgetter("misc", "name"), reverse=True)
        dining_info = dining_info[0:5]

        restaurant_info = db.execute("SELECT * FROM tags INNER JOIN locations ON tags.location_id = locations.id AND tags.label_id = 4")

        for location in restaurant_info:
            location["misc"] = float("{0:.3f}".format(restaurantRate(location)))

        restaurant_info = sorted(restaurant_info, key=itemgetter("misc", "name"), reverse=True)
        restaurant_info = restaurant_info[0:5]

        housing_info = db.execute("SELECT * FROM tags INNER JOIN locations ON tags.location_id = locations.id AND tags.label_id = 5")

        for location in housing_info:
            location["misc"] = float("{0:.3f}".format(housingRate(location)))

        housing_info = sorted(housing_info, key=itemgetter("misc", "name"), reverse=True)
        housing_info = housing_info[0:5]

        dating_info = db.execute("SELECT * FROM tags INNER JOIN locations ON tags.location_id = locations.id AND tags.label_id = 8")

        for location in dating_info:
            location["misc"] = float("{0:.3f}".format(datingRate(location)))

        dating_info = sorted(dating_info, key=itemgetter("misc", "name"), reverse=True)
        dating_info = dating_info[0:5]

        tags = db.execute("SELECT * FROM tags WHERE location_id = :location_id AND (label_id = 3 OR label_id = 4)", location_id=g_location_id)

        if len(tags) != 0:
            food = True
        else:
            food = False

        return render_template("index.html", food = food, rand_location = rand_location, dining_info = dining_info, restaurant_info = restaurant_info, housing_info = housing_info, dating_info = dating_info)

    # # Pulls out latest 5 entries from ratings table
    # latest = db.execute("SELECT * FROM (SELECT * FROM ratings ORDER BY datetime DESC LIMIT 0,5) ORDER BY datetime DESC")

    # numLocations = db.execute("SELECT Count(*) FROM locations")

    # r_num = random.randint(0, 100)

    # r_location = db.execute("SELECT * FROM locations WHERE id = :r_num", r_num=r_num)

    # # renders index.html page with correctly formatted values
    # return render_template("index.html", latest=latest, r_location=r_location)

def diningRate(location):
    rating = (location["popularity"] + location["conducivity"] + (0.2 * (location["love"] + location["litness"]))) * (math.sqrt(location["deviance"] / 3.0))
    rating = rating / (1.2)
    return rating

def restaurantRate(location):
    rating = (location["popularity"] + location["conducivity"] + (0.6 * location["love"]) + (0.4 * location["litness"])) * (math.sqrt(location["deviance"] / 3.0))
    rating = rating / (1.5)
    return rating

def housingRate(location):
    rating = (location["conducivity"] + location["litness"] + (0.2 * (location["popularity"] + location["love"]))) * (math.sqrt(location["deviance"] / 3.0))
    rating = rating / (1.2)
    return rating

def datingRate(location):
    rating = (location["love"] + (0.6 * location["conducivity"]) + (0.2 * location["litness"]) - (0.2 * (location["popularity"] - 3))) * (math.sqrt(location["deviance"] / 3.0))
    rating = rating / (1.0)
    return rating


@app.route("/location/<location_id>", methods=["GET", "POST"])
@login_required
@check_confirmed
def location(location_id):

    """Shows latest location ratings and generates random location"""

    informations = db.execute("SELECT * FROM locations WHERE id = :location_id", location_id=location_id)

    information = informations[0]

    if request.method == "POST":

        db.execute("INSERT INTO wishes (user_id, location_id) VALUES (:user_id, :location_id)", user_id=session["user_id"], location_id=information["id"])

        flash("Added to Wishlist!")

        return render_template("location.html", information=information)

    else:

        return render_template("location.html", information=information)


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


@app.route("/user/<user_id>")
# @login_required
# @check_confirmed
def profile(user_id):

    favorite_places = db.execute("SELECT DISTINCT name, href FROM wishes INNER JOIN locations ON wishes.location_id = locations.id WHERE user_id = :user_id", user_id = user_id)

    try:
        user = db.execute("SELECT username, registered_on FROM users WHERE id = :user_id", user_id = user_id)[0]
    except:
        return render_template("invalid.html")

    num_rated = db.execute("SELECT COUNT(user_id) FROM ratings WHERE user_id = :user_id", user_id = user_id)[0]["COUNT(user_id)"]

    return render_template("profile.html", user_id = user_id, favorite_places = favorite_places, username = user["username"], registered_on = user["registered_on"], ratings = num_rated)


@app.route("/search")
@login_required
@check_confirmed
def search():
    query = request.args.get("q") + '%'
    search_results = db.execute("SELECT id, name FROM locations WHERE name LIKE :name", name = query)
    print(search_results)
    return jsonify(search_results)


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


@app.route("/account")
@login_required
@check_confirmed
def account():

    user = db.execute("SELECT username, email, registered_on FROM users WHERE id = :user_id", user_id = session["user_id"])[0]

    return render_template("overview.html", username = user["username"], email = user["email"], registered_on = user["registered_on"][:10])


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


@app.route("/the-project", methods = ["GET"])
def information():
    return render_template("team.html")


@app.route("/rate/<r_location_id>", methods=["GET", "POST"])
@login_required
@check_confirmed
def rate(r_location_id):
    if request.method == "POST":
        print("hi")
        mood = request.form.get("mood")
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
        print(r_location_id)
        # dont need to error check because something will always be input
        frequency = request.form.get("frequency")
        busy = request.form.get("busy")
        conducive = request.form.get("conducive")
        lit = request.form.get("lit")
        deviance = request.form.get("deviance")
        romance = request.form.get("romance")
        print(r_location_id)
        db.execute("INSERT INTO ratings (user_id, location_id, mood, frequency, popularity, conducivity, litness, deviance, love) VALUES (:user_id, :location_id, :mood, :frequency, :busy, :conducive, :lit, :deviance, :romance)",
                    user_id = session["user_id"], location_id = r_location_id, mood = mood, frequency = frequency, busy = busy, conducive = conducive, lit = lit, deviance = deviance, romance = romance)
        print(r_location_id)
        updateRatings(r_location_id)
        print(r_location_id)
        flash("Thank you for rating!")

        return redirect("/")

    if request.method == "GET":
        print(r_location_id)
        informations = db.execute("SELECT * FROM locations WHERE id = :location_id", location_id=r_location_id)
        print(r_location_id)
        tags = db.execute("SELECT * FROM tags WHERE location_id = :location_id AND (label_id = 3 OR label_id = 4)", location_id=r_location_id)

        if len(tags) != 0:
            food = True
        else:
            food = False
        print(r_location_id)
        information = informations[0]

        return render_template("rate.html", information = information, food = food)


def updateRatings(location_id):
    ratings = db.execute("SELECT * FROM ratings WHERE location_id = :location_id", location_id=location_id)

    time1 = datetime.datetime.now()
    moods = []
    frequencies = []
    popularities = []
    conducivities = []
    litnesses = []
    deviances = []
    romances = []
    weights = []

    for rating in ratings:
        mult = 0.0
        difference = time1 - datetime.datetime.strptime(rating["datetime"], '%Y-%m-%d %H:%M:%S')
        diff_secs = difference.total_seconds()
        if diff_secs < 31536000.0:
            mult += 0.5
            if diff_secs < 15768000.0:
                mult += 0.3
                if diff_secs < 2628000.0:
                    mult += 0.1
                    if diff_secs < 604800.0:
                        mult += 0.1

        moods.append(rating["mood"])
        frequencies.append(rating["frequency"] * mult)
        popularities.append(rating["popularity"] * mult)
        conducivities.append(rating["conducivity"] * mult)
        litnesses.append(rating["litness"] * mult)
        deviances.append(rating["deviance"] * mult)
        romances.append(rating["love"] * mult)
        weights.append(mult)

    mood = mode(moods)
    frequency = float("{0:.3f}".format(sum(frequencies) / sum(weights)))
    popularity = float("{0:.3f}".format(sum(popularities) / sum(weights)))
    conducivity = float("{0:.3f}".format(sum(conducivities) / sum(weights)))
    litness = float("{0:.3f}".format(sum(litnesses) / sum(weights)))
    deviance = float("{0:.3f}".format(sum(deviances) / sum(weights)))
    love = float("{0:.3f}".format(sum(romances) / sum(weights)))

    db.execute("UPDATE locations SET mood = :mood, frequency = :frequency, popularity = :popularity, conducivity = :conducivity, litness = :litness, deviance = :deviance, love = :love WHERE id = :location_id",
                mood=mood, frequency=frequency, popularity=popularity, conducivity=conducivity, litness=litness, deviance=deviance, love=love, location_id=location_id)

# @app.route('/location/<location_id>')
# @login_required
# def location(location_id):
#     return apology("nothing here big boy")


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
