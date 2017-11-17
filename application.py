from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

import random

# Configure application
app = Flask(__name__)

# Ensure responses aren't cached


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

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///campusguide.db")


@app.route("/")
@login_required
def index():
    """Shows latest location ratings and generates random location"""

    # Pulls out latest 5 entries from ratings table
    latest = db.execute("SELECT * FROM (SELECT * FROM ratings ORDER BY datetime DESC LIMIT 0,5) ORDER BY datetime DESC")

    numLocations = db.execute("SELECT Count(*) FROM locations")

    r_num = random.randint(0, 100)

    r_location = db.execute("SELECT * FROM locations WHERE id = :r_num", r_num=r_num)

    # renders index.html page with correctly formatted values
    return render_template("index.html", latest=latest, r_location=r_location)

'''
@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensures symbol was provided
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 400)

        # Ensures shares was provided
        elif not request.form.get("shares"):
            return apology("must provide shares", 400)

        # Ensures shares is an integer
        try:
            int(request.form.get("shares"))
        except ValueError:
            return apology("must provide positive integer number of shares", 400)

        # Ensures shares is positive
        if int(request.form.get("shares")) < 1:
            return apology("must provide positive integer number of shares", 400)

        # Stores symbol
        symbol = request.form.get("symbol")

        # Stores shares
        shares = int(request.form.get("shares"))

        # Looks up stock data
        data = lookup(symbol)

        # Ensures valid stock symbol
        if data is None:
            return apology("stock symbol not found", 400)

        rows = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session["user_id"])

        # Stores current cash
        current_cash = rows[0]["cash"]

        # Calculates cash needed for transaction
        transaction_cash = data["price"] * shares

        # Ensures enough cash present
        if transaction_cash > current_cash:
            return apology("can't afford", 400)

        # Inserts all transaction information into table
        db.execute("INSERT INTO transactions (symbol, name, shares, price, total, user_id, type) VALUES (:symbol, :name, :shares, :price, :total, :user_id, 'buy')",
                   symbol=data["symbol"], name=data["name"], shares=shares, price=data["price"], total=transaction_cash, user_id=session["user_id"])

        # Subtracts transaction amount from cash
        current_cash -= transaction_cash

        # Updates user's cash
        db.execute("UPDATE users SET cash = :cash WHERE id = :user_id",
                   cash=current_cash, user_id=session["user_id"])

        # Pulls out any pre-existing holdings of the stock from portfolios table
        holdings = db.execute("SELECT * FROM portfolios WHERE user_id = :user_id AND symbol = :symbol",
                              user_id=session["user_id"], symbol=symbol)

        # If non-existent, creates a holding in the portfolios table
        if len(holdings) == 0:
            db.execute("INSERT INTO portfolios (user_id, symbol, shares, price, total, name) VALUES (:user_id, :symbol, :shares, :price, :total, :name)",
                       user_id=session["user_id"], symbol=data["symbol"], shares=shares, price=data["price"], total=transaction_cash, name=data["name"])

        # Otherwise, updates holding in the portfolios table
        else:
            holdings[0]["shares"] += shares

            holdings[0]["total"] += transaction_cash

            db.execute("UPDATE portfolios SET shares = :shares, total = :total WHERE user_id = :user_id AND symbol = :symbol",
                       shares=holdings[0]["shares"], total=holdings[0]["total"], user_id=session["user_id"], symbol=symbol)

        # Notifies successful transaction
        flash("Bought!")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")
'''

# ********** PERSONALIZATION ASSIGNMENT *********** #


@app.route("/change-password", methods=["GET", "POST"])
@login_required
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
        if password == request.form.get("current_password"):
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

'''
@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Pulls out all transactions the user has made, already ordered by datetime
    rows = db.execute("SELECT * FROM transactions WHERE user_id = :user_id",
                      user_id=session["user_id"])

    # Formats prices correctly
    for row in rows:
        row["price"] = usd(row["price"])

    # Generates table of transactions
    return render_template("history.html", rows=rows)
'''


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

        # Redirect user to home page
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


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    """Search for a location."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensures symbol was provided
        if not request.form.get("location"):
            return apology("must provide location", 400)

        # Stores symbol
        location = request.form.get("location")

        # Looks up data
        data = db.execute("SELECT * FROM locations WHERE name = :name", name=location)

        # Ensures stock symbol was valid
        if len(data) == 0:
            return apology("location not found", 400)

        # Renders quoted page with properly formatted information
        return render_template("results.html", data=data)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("search.html")


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
        db.execute("INSERT INTO users (username, hash, email) VALUES (:username, :p_hash, :email)",
                   username=username, p_hash=str(p_hash), email=email)

        flash("Registered!")

        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

'''
@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensures symbol was provided
        if not request.form.get("symbol"):
            return apology("must provide stock symbol", 400)

        # Ensures shares was provided
        elif not request.form.get("shares"):
            return apology("must provide shares", 400)

        # Pulls out relevant holdings from portfolios table
        holdings = db.execute("SELECT * FROM portfolios WHERE user_id = :user_id AND symbol = :symbol",
                              user_id=session["user_id"], symbol=request.form.get("symbol"))

        # ensures shares is an integer
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("must provide positive integer number of shares", 400)

        # ensures shares is positive
        if shares < 1:
            return apology("must provide positive integer number of shares", 400)

        # Looks up data
        data = lookup(request.form.get("symbol"))

        # Ensures holdings exist
        if len(holdings) == 0:
            return apology("no shares to sell", 400)

        # Ensures enough shares exist to be sold
        if holdings[0]["shares"] < shares:
            return apology("not enough shares", 400)

        # Calculates new number of shares
        holdings[0]["shares"] -= shares

        # Calculates total transaction amoount
        transaction_cash = holdings[0]["price"] * shares

        # If sold all sahres, deletes holding from portfolios table
        if holdings[0]["shares"] == 0:
            db.execute("DELETE FROM portfolios WHERE user_id = :user_id AND symbol = :symbol",
                       user_id=session["user_id"], symbol=request.form.get("symbol"))

        # Otherwise, updates portfolios table with new holding information
        else:
            holdings[0]["total"] -= transaction_cash

            db.execute("UPDATE portfolios SET shares = :shares, total = :total WHERE user_id = :user_id AND symbol = :symbol",
                       shares=holdings[0]["shares"], total=holdings[0]["total"], user_id=session["user_id"], symbol=request.form.get("symbol"))

        # Pulls out user information
        users = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session["user_id"])

        # Calculates increase in cash with transaction amount
        users[0]["cash"] += transaction_cash

        # Updates cash in users table
        db.execute("UPDATE users SET cash = :cash WHERE id = :user_id",
                   cash=users[0]["cash"], user_id=session["user_id"])

        # Inserts transaction information into transactions table
        db.execute("INSERT INTO transactions (symbol, name, shares, price, total, user_id, type) VALUES (:symbol, :name, :shares, :price, :total, :user_id, 'sell')",
                   symbol=data["symbol"], name=data["name"], shares=shares, price=data["price"], total=transaction_cash, user_id=session["user_id"])

        # Notifies successful transaction
        flash("Sold!")

        # Redirects user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:

        # Pulls out all holdings to be displayed in web page
        holdings = db.execute("SELECT * FROM portfolios WHERE user_id = :user_id",
                              user_id=session["user_id"])

        # Renders sell page
        return render_template("sell.html", holdings=holdings)
'''

def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
