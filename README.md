# Vulnerable_LAB — Deliberately Vulnerable Web Application



> ⚠️ For educational and research purposes only. Never deploy this to a public or production server.

---

## What is this?

Vulnerable_LAB is a web application I built from scratch to practice and demonstrate real web application vulnerabilities. Instead of just running tools against someone else's app, I wrote the vulnerable code myself — which means I understand exactly why each vulnerability exists, how to exploit it, and how to fix it.

The app has a full user system with registration and login, a home dashboard with cards for each vulnerability, and four separate attack surfaces to explore. Everything is intentionally broken in specific ways that mirror how these vulnerabilities actually appear in real production code.

---

## Vulnerabilities

| # | Vulnerability | Severity | OWASP 2021 |
|---|--------------|----------|------------|
| 1 | Cross-Site Scripting (XSS) — 5 levels | High | A03 Injection |
| 2 | Insecure Direct Object Reference (IDOR) | High | A01 Broken Access Control |
| 3 | SQL Injection — Login bypass | High | A03 Injection |
| 4 | Unrestricted File Upload | Medium | A04 Insecure Design |

---

## Project Structure

```
Vulnerable Website/
├── app.py                      # All Flask routes and vulnerability logic
├── user_detail.db              # SQLite database — auto-created on first run
├── requirements.txt
│
├── static/
│   ├── styles/
│   │   └── style.css           # Custom stylesheet used across all pages
│   └── uploads/                # Uploaded files are saved here (created at runtime)
│
└── templates/
    ├── index.html              # Homepage — four vulnerability cards with Visit buttons
    ├── login.html              # Login page (also the SQL injection target)
    ├── register.html           # Register page
    ├── xss.html                # XSS playground — 5 levels on one page
    ├── profile.html            # IDOR target — shows user data with Prev/Next navigation
    ├── upload.html             # File upload — shows access link after upload
    └── check_vul.html          # JS eval shell — uploaded to demo file upload vuln
```

---

## Getting it running

You need Python 3.8 or above.

```bash
# Clone the repo
git clone https://github.com/PrashantJargad/Vulnerable_LAB.git
cd vulnlab

# Install dependencies
pip install -r requirement.txt

# Set the secret key — required for Flask sessions to work
set SECRET=anysecretvalue        # Windows
export SECRET=anysecretvalue     # Linux / Mac

# Start the app
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

---

## First time setup — register two accounts

Go to `/register` and create two test accounts:

- `alice@test.com` — password: `alice123`
- `bob@test.com` — password: `bob123`

Having two accounts matters. You need them to properly demonstrate the IDOR vulnerability — log in as Alice, then access Bob's profile by changing the ID in the URL.

---

## Navigating the app

After logging in you land on the homepage. It shows four cards, one for each vulnerability, each with a short description and a Visit button.

```
XSS card         →  /xss
IDOR card        →  /profile/<your_user_id>
SQL Injection    →  /login
File Upload      →  /upload
```

The SQLi card links to `/login` because that's where the vulnerable query lives — you exploit it by logging in with an injected email rather than a real password.

---

## Vulnerability writeups

---

### 1. Cross-Site Scripting (XSS)

**Page:** `/xss`

Five levels, all on one page. Each card has its own input form and hidden `level` field that tells Flask which context to reflect your input into. The levels get progressively harder — each one simulates a developer who tried to protect the input but left a gap.

**Level 1 — No protection at all**

Input is passed through `Markup()` in Flask, which tells Jinja2 to trust the string and not escape it. Whatever you type renders as raw HTML.

```
Payload:  <script>alert('XSS Level 1')</script>
```

**Level 2 — Input tag attribute breakout**

Your input lands inside `value=""` of an `<input>` tag. The template uses `{{result}}` directly in the attribute without escaping. A `"` closes the attribute value, `>` closes the tag, and your script tag runs in free HTML.

```
Payload:  "><script>alert('Level 2')</script>
```

```html
<!-- xss.html — unescaped in attribute -->
<input value="{{result}}">
```

**Level 3 — Filter evasion**

The server runs `payload.replace("script", "")` before reflecting the input. One replace pass isn't enough — nesting `script` inside itself means the filter removes the inner copy and the outer one re-forms.

```
Payload:  <sscriptcript>alert('Level 3')</sscriptcript>
```

```python
# app.py
filtered = payload.replace("script", "")
# sscriptcript  →  remove inner 'script'  →  script  ✓
result = Markup(filtered)
```

**Level 4 — Image attribute breakout**

Input goes into `<img src="{{ result | safe }}">`. You can't use `<script>` directly, but you can inject an event handler. Close the src attribute with a `"`, add `onerror=`, and when the broken image fails to load your code runs.

```
Payload:  x" onerror="alert('Level 4')
```

**Level 5 — JavaScript string breakout**

Input is embedded directly into a JS variable: `var currentUsername = "{{ result | safe }}";`. Close the string with `"`, inject your code, then add `//` to comment out the trailing `";` — the page loads normally with no syntax error.

```
Payload:  ";alert('Level 5')//
```

```html
<!-- xss.html -->
<script>
    var currentUsername = "{{ result | safe }}";
    console.log("Welcome to the system, " + currentUsername);
</script>
```

**The fix for all five levels:** Remove `Markup()` and stop using `| safe` on user input. Jinja2 auto-escapes `{{ result }}` by default. For JavaScript contexts specifically, use `{{ value | tojson }}` which wraps the value in proper JS encoding.

---

### 2. Insecure Direct Object Reference (IDOR)

**Page:** `/profile/<user_id>`

The IDOR card takes you to your own profile at `/profile/1` (if you registered first). The page shows a table with your ID, email, role, and password. It also has Previous user and Next user buttons.

The vulnerability is that the route never checks whether the ID in the URL belongs to the person who is logged in. Change the `1` to a `2` in the URL bar and you see Bob's full profile — including his password, shown in red with a warning banner.

```
Your profile:     /profile/1   →  your own data, green banner
Change URL to:    /profile/2   →  bob's email + password exposed, red banner
Keep going:       /profile/3   →  next user, and so on
```

The Previous / Next buttons on the profile page make enumeration even easier — you can walk through every registered user without touching the URL bar.

```python
# app.py — the check that should be here is intentionally missing
@app.route('/profile/<int:user_id>')
def profile(user_id):
    # MISSING: if user_id != session['user_id']: abort(403)
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return render_template('profile.html', user=user,
                           is_own=(user_id == session['user_id']))
```

**The fix:** One line before the query — `if user_id != session['user_id']: abort(403)`.

---

### 3. SQL Injection — Login Bypass

**Page:** `/login`

The login page looks normal. The vulnerability is in the Flask route — the email value is dropped directly into an f-string to build the SQL query. Injecting `'--` after a real email address turns everything after it into a SQL comment, so the password check never runs.

```
To log in as whoever registered first:
  Email field:     ' OR '1'='1' --
  Password field:  alice password 
```

```python
# app.py — vulnerable f-string
cursor.execute(f"SELECT * FROM users WHERE email ='{email}'")

# After injection the database sees:
# SELECT * FROM users WHERE email ='alice@test.com' --'
# Everything from -- onwards is a comment — login succeeds
```

Notice the login form uses `type="text"` on the email field (not `type="email"`) — this is intentional so the browser doesn't block special characters like `'` and `-`.

**The fix:**

```python
cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
```

---

### 4. Unrestricted File Upload

**Page:** `/upload`

The upload page accepts any file. After uploading, it shows a direct link to the file at `/static/uploads/filename`. No extension check, no MIME type validation, no filename sanitisation.

**Demo 1 — JS eval shell via upload**

The repo includes `check_vul.html` — a ready-made JavaScript eval shell. Upload it, then click the access link. You get a terminal-style page where anything you type gets passed to `eval()` in the browser.

```
Try these in the shell:
  document.cookie          →  shows your Flask session cookie
  document.domain          →  shows the domain
  localStorage             →  dumps local storage
  navigator.userAgent      →  browser info
```

**Demo 2 — Stored XSS via HTML upload**

Create any `.html` file with a script tag and upload it. The file is served directly by Flask from the static folder, so the browser renders it as a full webpage and the script runs.

```html
<script>alert('XSS via upload — cookie: ' + document.cookie)</script>
```

**Demo 3 — Path traversal via Burp Suite**

Intercept the upload POST request in Burp Suite and change the `filename` in the multipart body to `../../app.py`. The server saves the file to that path, overwriting your Flask application source.

```python
# app.py — no validation whatsoever
save_path = os.path.join('static', 'uploads', file.filename)
file.save(save_path)
```

**The fix:**

```python
from werkzeug.utils import secure_filename

ALLOWED = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
ext = file.filename.rsplit('.', 1)[-1].lower()
if ext not in ALLOWED:
    return "File type not allowed", 400
filename = secure_filename(file.filename)
save_path = os.path.join('static', 'uploads', filename)
```

---

## What I learned building this

Writing every vulnerability from scratch forced me to understand the mechanics behind each one in a way that just running tools never would.

For the XSS levels I had to understand each HTML context separately — what makes an attribute context different from a script context, why `.replace()` fails as a filter, and why `Markup()` specifically breaks Jinja2's security model. For the SQL injection I had to understand what parameterised queries actually do at the database level, not just that they "fix SQLi". For IDOR I realised how easy it is to build a feature that works correctly but forgets the authorisation check entirely. And with file upload I learned that there are at least three separate failure points — extension, MIME type, and path — and each one needs to be addressed independently.

---

## Disclaimer

This app is intentionally broken. Run it locally only. Do not deploy it anywhere public, do not store real credentials in it, and do not use any of these techniques against systems you do not own or have explicit permission to test.

---

## Author

Built as part of a personal cybersecurity portfolio project covering OWASP Top 10 web vulnerabilities.  
Certifications: TryHackMe SOC L1 · TryHackMe Jr Penetration Tester
