Phishy URL Detector
Video Demo: <https://drive.google.com/drive/folders/1rO7OjJEgC_yU2sS_75zEQReblZ8NvNd5?usp=sharing>
Description:

Phishy URL Detector is a Flask web application that lets a logged-in user paste in any URL and immediately see whether it exhibits common, well-documented signs of a phishing link. It was built as my CS50x final project on top of the CS50 "Finance" web app skeleton (Bootstrap + Flask + SQLite + Jinja templating), reusing the authentication scaffolding from that problem set and replacing the stock-trading logic with a URL-analysis engine of my own design.

The motivation behind the project is simple: phishing is still one of the most common ways people get their accounts and money stolen, and most phishing links share a handful of structural "tells" that are easy to check for programmatically even without a live threat-intelligence feed or an internet connection. Rather than trying to build a full machine-learning classifier — which would require a labeled dataset, training pipeline, and far more time than a final project allows — I chose to implement a transparent, rule-based heuristic scorer. Every verdict the app gives can be explained in plain English to the user, which felt more valuable for a learning tool than a black-box prediction.

Features
User registration and login. Passwords are never stored in plaintext; they are hashed with werkzeug.security.generate_password_hash and verified with check_password_hash, exactly as in the CS50 Finance problem set. Sessions are managed server-side with Flask-Session.
URL submission and verdict. A logged-in user can paste any URL into a form and receive an immediate "phishy" or "safe" verdict, along with a human-readable list of exactly which red flags fired.
Ten-signal heuristic scorer. detect_phishing() in helpers.py checks for:
Raw IP address used in place of a domain name (e.g. http://192.168.1.1/login)
@ symbols in the URL, which browsers historically ignored everything before them when resolving the host
Excessive hyphens in the domain (a common typosquatting trick, e.g. paypal-secure-login.com)
Excessive overall URL length
Excessive number of subdomains (e.g. secure.login.paypal.com.verify.ru)
Known URL-shortener domains (bit.ly, tinyurl.com, etc.), which hide the true destination
Missing HTTPS
Suspicious keywords in the path or query string (login, verify, secure, account, update, confirm, ...)
Suspicious top-level domains that are disproportionately favored by phishing campaigns (.xyz, .tk, .top, .club, ...)
Basic brand typosquatting — Levenshtein-style comparison of the domain against a small list of frequently impersonated brands (PayPal, Apple, Amazon, Microsoft, banks, etc.) to catch near-misses like paypa1.com
Point-threshold scoring. Each triggered signal adds one point; a score of 2 or higher is classified "phishy," anything lower is "safe." The threshold is a single constant in helpers.py, deliberately isolated so it can be tuned without touching the detection logic itself.
Persistent logging. Every URL a user checks — along with the verdict, the individual flags that fired, and a timestamp — is written to a detect table in the SQLite database, so a user can review their check history.
Project structure
phishing-url-detector/
├── app.py                     # Flask routes: /login, /register, /logout, /
├── helpers.py                 # apology(), login_required, detect_phishing()
├── url.db                     # SQLite database (user, detect tables)
├── static/
│   └── style.css              # Custom styling on top of Bootstrap
└── templates/
    ├── layout.html            # Shared navbar/footer, Bootstrap includes
    ├── login.html
    ├── register.html
    ├── apology.html           # Reused CS50-style error page
    └── url_detector.html      # Form + results display
app.py

Defines the Flask routes. /register and /login follow the same pattern as CS50 Finance: form validation, duplicate-username checks, and session-based auth via login_required. The core route, / (rendered as url_detector.html), accepts a POST with a url field, calls detect_phishing() from helpers.py, inserts a row into the detect table via the cs50 SQL wrapper, and re-renders the page with the verdict and triggered flags.

helpers.py

Houses three things:

apology() — the same friendly error-page helper used throughout CS50 problem sets, reused here for invalid input (e.g. a malformed URL, an empty submission).
login_required — a decorator that redirects anonymous users to /login before they can reach the checker page, exactly matching the CS50 Finance implementation.
detect_phishing(url) — the heart of the project. It parses the URL with Python's built-in urllib.parse, runs it through the ten checks listed above, accumulates a score, and returns a tuple of (verdict, flags) where flags is a list of strings describing which signals fired, so the template can display them directly to the user instead of just a bare yes/no.
url.db

A SQLite database with two tables:

users — id, username, hash (hashed password)
detect — id, user_id, url, verdict, flags, timestamp
templates/

Standard Jinja templates extending a shared layout.html. url_detector.html contains the submission form and, conditionally, a results card showing the verdict in a colored Bootstrap alert (red for phishy, green for safe) and a bulleted list of the specific red flags detected.

Design decisions

Why a rule-based heuristic instead of machine learning? A trained classifier would need a real labeled dataset of phishing vs. legitimate URLs, a training/evaluation pipeline, and a way to serialize and load the model inside the app — a lot of surface area for a project whose real learning goal was full-stack web development with Flask. A heuristic scorer lets the app stay fully self-contained, deterministic, and explainable: the user always knows why a URL was flagged, which matters a lot for a security-education tool.

Why a point threshold instead of individual pass/fail? Almost every individual signal has legitimate exceptions (plenty of real sites use hyphens or long URLs), so treating any single flag as disqualifying would produce too many false positives. Summing weighted signals and applying a threshold reduces false positives while still catching URLs that combine several classic phishing traits.

Why log every check? Beyond satisfying the "at least one database table beyond the CS50-provided one" style requirement, a history view lets a user see patterns in what they've been checking and revisit a verdict without re-pasting the URL.

Setup
Install dependencies:
   pip install cs50 flask flask-session
Run the app:
   flask run
Open the printed local URL in your browser.
Usage
Register an account.
Log in.
Go to the URL checker page, paste in a URL, and hit Check.
Review the verdict and the list of red flags that triggered it.
Optionally revisit past checks from your account's history.
Limitations and future work
The brand-typosquatting list is small and hand-curated; a production tool would pull from a much larger, regularly updated brand list.
The tool has no access to live threat-intelligence feeds (e.g. Google Safe Browsing, PhishTank), so it cannot catch a phishing page hosted on an otherwise "clean-looking" domain.
The scoring weights are currently uniform (every flag = 1 point); a natural extension would be to weight signals by how strongly they correlate with real phishing in practice.
A browser extension front-end, so URLs could be checked before a user ever clicks them, is a natural next step beyond the current web-form interface.
