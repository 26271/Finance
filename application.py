import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


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
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get user's cash
    user = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

    # Get portfolio
    portfolios = db.execute("SELECT * FROM portfolios WHERE user_id = ?", session["user_id"])

    # Get symbol for each stock
    length = len(portfolios)
    for i in range(length):
        symbol = portfolios[i]['stocks']

        # Lookup stock price and add to portfolio information
        portfolios[i]['price'] = lookup(symbol)['price']
        portfolios[i]['total'] = float(portfolios[i]['price']) * portfolios[i]['shares']

    # Calculate total value of stocks
    value = 0
    for j in range(length):
        value += portfolios[j]['price']

    # Calculate grand total of stocks plus cash
    g_total = user[0]["cash"] + value

    return render_template("index.html", portfolios=portfolios, cash=user[0]["cash"], g_total=g_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy stocks"""
    # User submitted data via POST
    if request.method == "POST":

        # Ensure symbol is entered
        if not request.form.get("symbol"):
            return apology("must enter stock symbol")

        # Ensure stock exists
        symbol = request.form.get("symbol")
        if not lookup(symbol):
            return apology("stock doesn't exist")

        # Ensure positive number of shares entered
        shares1 = request.form.get("shares")
        if not isinstance(shares1, int) or shares1 <= 0:
            return apology("must enter a positive whole number")

        # Ensure user has enough funds
        user = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = user[0]["cash"]
        price = lookup(symbol)['price']
        name = lookup(symbol)['name']
        total = shares1 * price
        if cash < total:
            return apology("insufficient funds")

        # Save purchase into database
        day = datetime.now()
        time = datetime.now().time()

        # Save in transactions history
        db.execute("INSERT INTO transactions (user_id, date, time, stock, name, price, shares, total, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   session["user_id"], day, time, symbol, name, price, shares1, total, "buy")

        # Update portfolios table
        # Check if stock is already added
        exists = db.execute("SELECT * FROM portfolios WHERE user_id = ? AND stocks = ?", session["user_id"], symbol)

        # If it exists, update shares
        if exists:
            db.execute("UPDATE portfolios SET shares = shares + ? WHERE user_id = ? AND stocks = ?",                    
                       shares1, session["user_id"], symbol)

        # Else insert record
        else:
            db.execute("INSERT INTO portfolios SELECT user_id, shares, stock, name FROM transactions WHERE user_id = ? AND type = ? AND stock = ? AND date = ? AND time = ?", 
                       session["user_id"], "buy", symbol, day, time)

        # Update cash amount
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - total, session["user_id"])

        # Show stats on index page
        return redirect("/")

    # User used a link to reach page
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC, time DESC", session["user_id"])

    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Access profile to change password"""

    # User entered new password
    if request.method == "POST":

        # Ensure current password entered
        if not request.form.get("old"):
            return apology("Please enter current password")

        # Query database for current password
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Ensure old password matches current password
        if not check_password_hash(rows[0]["hash"], request.form.get("old")):
            return apology("Invalid password")

        # Ensure user entered a new password
        if not request.form.get("new"):
            return apology("Please enter a new password")

        # Ensure old and new passwords are different
        if request.form.get("new") == request.form.get("old"):
            return apology("Must enter a new password")

        # Update new password in database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(
            request.form.get("new"), method='pbkdf2:sha256', salt_length=8), session["user_id"])

        # Redirect to homepage
        return redirect("/")

    else:

        # User reached page via a link
        return render_template("profile.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("Please enter a stock symbol")

        # Get user input
        symbol = request.form.get("symbol")
        
        # Ensure is a valid stock symbol
        if not lookup(symbol):
            return apology("Invalid stock symbol")

        # Submit user input to get a quote and display to user
        return render_template("quoted.html", quote=lookup(symbol))

    # User reached page via GET (clicking on link or a redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Query database and check if username already in use
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Send apology message if username already taken
        if len(rows) == 1:
            return apology("Username not available", 403)

        # Ensure password submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure password matches confirmation password
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords must match", 403)

        # Insert new user into database and hash password
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), 
                   generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8))

        # Redirect to homepage
        return redirect("/")

    # User reached route via GET (by clicking on a link or by redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User submits information
    if request.method == "POST":

        # Ensure user entered a stock
        if not request.form.get("symbol"):
            return apology("must choose a stock")

        # Get stock selected
        symbol = request.form.get("symbol")
        
        # Ensure is a valid stock symbol
        if not lookup(symbol):
            return apology("Invalid stock symbol")

        # Ensure user owns the stock requested
        test = db.execute("SELECT * FROM portfolios WHERE user_id = ? AND stocks = ?", session["user_id"], symbol)

        if not test:
            return apology("you have 0 shares of this stock")

        owns = db.execute("SELECT * FROM portfolios WHERE user_id = ? AND stocks = ?", session["user_id"], symbol)

        # Ensure user entered a number in shares
        if not request.form.get("shares") or not isinstance(request.form.get("shares"), int):
            return apology("must enter postive whole number of shares")

        shares = request.form.get("shares")

        # Ensure number is positive
        if shares <= 0:
            return apology("must enter a positive number")

        # Ensure user owns the amount of stock entered to sell
        if shares > owns[0]['shares']:
            return apology("you don't own that much of this stock")

        # Get date and time for transaction
        day = datetime.now()
        time = datetime.now().time()

        # Get total and stock name for transaction
        price = lookup(symbol)['price']
        total = price * shares
        name = lookup(symbol)['name']

        # Sell shares of the stock and add to transactions history
        db.execute("INSERT INTO transactions (user_id, date, time, price, shares, total, stock, name, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   session["user_id"], day, time, price, shares * -1, total, symbol, name, "sell")

        # Update portfolios table
        db.execute("UPDATE portfolios SET shares = shares - ? WHERE user_id = ? AND stocks = ?", shares, session["user_id"], symbol)

        # If stock shares is 0, delete from portfolio
        db.execute("DELETE FROM portfolios WHERE shares = ? ", 0)

        return redirect("/")

    # If user reached page via link or redirect
    else:

        # Get list of stocks owned
        owns = db.execute("SELECT stocks FROM portfolios WHERE user_id = ? ORDER BY stocks", session["user_id"])

        return render_template("sell.html", owns=owns)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
