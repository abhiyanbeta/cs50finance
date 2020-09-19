import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Setting API key
if not os.environ.get("API_KEY"):
    try:
        os.environ["API_KEY"] = "pk_0ed3a09887ba4d199bebbb9a3561d00f"
    except:
        raise RuntimeError("API_KEY not set")

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
# db = SQL("sqlite:///finance.db")
db = SQL("postgres://ksttbfusnqbjyk:0b754336d826def366d1718a3269b3efcbde507ec9c9dbec79f0335790abb8bf@ec2-54-228-250-82.eu-west-1.compute.amazonaws.com:5432/dcunpf7nq0m33c")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


# Function that allows you to add money
@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    if request.method == "POST":
        db.execute("""
        UPDATE users
        SET cash = cash + :amount
        WHERE id=:user_id
        """, amount=request.form.get("cash"),
                   user_id=session["user_id"])
        flash("Added cash!")
        return redirect("/")
    else:
        return render_template("add_cash.html")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Obtaining all the shares the current user owns
    rows = db.execute("""
        SELECT symbol, SUM(shares) as totalShares
        FROM transactions
        WHERE user_id = :user_id
        GROUP BY symbol
        HAVING totalShares > 0;
    """, user_id=session["user_id"])

    # Appending holdings into an empty array
    holdings = []
    grand_total = 0
    for row in rows:
        stock = lookup(row["symbol"])  # Lookup that stock symbol
        holdings.append({
            "symbol": stock["symbol"],
            "name": stock["name"],
            "shares": row["totalShares"],
            "price": usd(stock["price"]),
            "total": usd(stock["price"] * row["totalShares"])
        })

        grand_total += stock["price"] * row["totalShares"]

    # Obtain current cash user has
    rows = db.execute("SELECT cash FROM users WHERE id=:user_id", user_id=session["user_id"])
    cash = rows[0]["cash"]
    grand_total += cash

    # Display the table by rendering index html
    return render_template("index.html", holdings=holdings, cash=usd(cash), grand_total=usd(grand_total))


# Purchasing the stock
@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # POST request if user submits data
    if request.method == "POST":

        # User doesn't enter symbol or number of shares
        if not request.form.get("symbol"):
            return apology("No symbol provided", 400)
        elif not request.form.get("shares"):
            return apology("No shares specified", 400)
        # Number of shares is not a digit
        elif not request.form.get("shares").isdigit():
            return apology("Invalid number of shares", 400)

        # Check that symbol is valid
        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))

        stock = lookup(symbol)
        if stock is None:
            return apology("Invalid symbol", 400)

        # Check how much cash user has currently (aka if they can afford to buy it)
        rows = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
        cash = rows[0]["cash"]

        updated_cash = cash - shares * stock['price']
        # Insufficient funds
        if updated_cash < 0:
            return apology("Insufficient funds")
        # Sufficient funds so update user's cash
        db.execute("UPDATE users SET cash=:updated_cash WHERE id=:id",
                   updated_cash=updated_cash,
                   id=session["user_id"])
        # Add transaction into transaction history table
        db.execute("""
            INSERT INTO transactions (user_id, symbol, shares, price)
            VALUES (:user_id, :symbol, :shares, :price)
            """,
                   user_id=session["user_id"],
                   symbol=stock["symbol"],
                   shares=shares,
                   price=stock["price"]
                   )
        flash("Bought!")
        return redirect("/")

    else:  # GET request
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Obtain data from our transactions table
    transactions = db.execute("""
        SELECT symbol, shares, price, transacted
        FROM transactions
        WHERE user_id=:user_id
    """, user_id=session["user_id"])

    # To obtain price in USD format
    for i in range(len(transactions)):
        transactions[i]["price"] = usd(transactions[i]["price"])
    return render_template("history.html", transactions=transactions)


# Implemented already
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):  # Input name is username
            return apology("You must provide a username.", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("You must provide a password.", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("Invalid username and/or password.", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


# Already implemented
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    # Symbol sumbitted to look up
    if request.method == "POST":
        # Symbol not entered
        if not request.form.get("symbol"):
            return apology("Missing symbol", 400)

        # Obtain symbol name as variable for lookup
        symbol = request.form.get("symbol").upper()
        # Looks up the symbol
        stock = lookup(symbol)
        if stock == None:
            return apology("Invalid symbol", 400)

        # Display quoted stock price
        return render_template("quoted.html", stock={
            'name': stock['name'],
            'symbol': stock['symbol'],
            'price': usd(stock['price'])
        })
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


def validate(password):
    import re  # Import regular expressions
    if len(password) < 6:
        return apology("Password must be at least 6 characters")
    elif not re.search("[0-9]", password):  # No number entered
        return apology("Password must contain at least one number")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        # Validate password complexity
        validation_errors = validate(request.form.get("password"))

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("You must provide a username.", 403)
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("You must provide a password.", 403)
        elif validation_errors:  # Validate password complexity
            return validation_errors
        elif not request.form.get("confirmation"):
            return apology("You must re-type your password.", 403)
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("Your passwords do not match.", 403)

        # Ensure username not already used
        check_user_exists = db.execute("SELECT * FROM users WHERE username = :username",
                                       username=request.form.get("username"))
        if len(check_user_exists) == 1:
            return apology("Username already used. Please select another.", 403)
        else:  # Error-checking passed, proceed to create new user and log them in
            # Generate hashed password
            hashed_password = generate_password_hash(request.form.get("password"))
            # Insert new user into database
            db.execute("INSERT INTO users(username, hash) VALUES (:username, :hashed_password)",
                       username=request.form.get("username"), hashed_password=hashed_password)

            # Remember which user has just registered to log them in
            rows = db.execute("SELECT * FROM users WHERE username = :username",
                              username=request.form.get("username"))
            # Log in just registered user
            session["user_id"] = rows[0]["id"]

            # Redirect user to home page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # POST request if user submits data
    if request.method == "POST":

        # User doesn't enter symbol or number of shares
        if not request.form.get("symbol"):
            return apology("No symbol provided", 400)
        elif not request.form.get("shares"):
            return apology("No shares specified", 400)
        # Number of shares is not a digit
        elif not request.form.get("shares").isdigit():
            return apology("Invalid number of shares", 400)

        # Check that symbol is valid
        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))

        stock = lookup(symbol)
        if stock is None:
            return apology("Invalid symbol", 400)

        # Find out what they own
        rows = db.execute("""
            SELECT symbol, SUM(shares) as totalShares
            FROM transactions
            WHERE user_id=:user_id
            GROUP BY symbol
            HAVING totalShares > 0;
        """, user_id=session["user_id"])

        # Error checking
        for row in rows:
            if row["symbol"] == symbol:  # Symbol entered by user matches db
                if shares > row["totalShares"]:  # Seeing if user trying to sell more shares than they have
                    return apology("Too many shares.", 400)

        # Check how much cash user has currently (aka if they can afford to buy it)
        rows = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
        cash = rows[0]["cash"]

        # Update users cash
        updated_cash = cash + shares * stock['price']
        # Sufficient funds so update user's cash
        db.execute("UPDATE users SET cash=:updated_cash WHERE id=:id",
                   updated_cash=updated_cash,
                   id=session["user_id"])
        # Add transaction into transaction history table
        db.execute("""
            INSERT INTO transactions (user_id, symbol, shares, price)
            VALUES (:user_id, :symbol, :shares, :price)
            """,
                   user_id=session["user_id"],
                   symbol=stock["symbol"],
                   shares=-1 * shares,  # To represent selling shares
                   price=stock["price"]
                   )
        flash("Sold!")
        return redirect("/")

    else:  # GET request
        # Obtaining symbols user already owns to only allow selling those ones
        rows = db.execute("""
            SELECT symbol FROM transactions WHERE user_id=:user_id
            GROUP BY symbol
            HAVING SUM(shares) > 0;
        """, user_id=session["user_id"])
        return render_template("sell.html", symbols=[row["symbol"] for row in rows])


# Dw about this
def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
