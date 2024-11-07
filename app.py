import os
import base64
import hashlib
import requests
from flask import Flask, redirect, request, session, url_for, render_template_string
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import secrets

# Load environment variables
load_dotenv()
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
CALLBACK_URL = os.getenv("CALLBACK_URL")

# Ensure that the environment variables are loaded
print(f"Client ID: {CLIENT_ID}")
print(f"Client Secret: {CLIENT_SECRET}")
print(f"Callback URL: {CALLBACK_URL}")

# Initialize Flask app
app = Flask(__name__)

# Secure session key for Flask session handling
app.secret_key = secrets.token_urlsafe(32)  # Use a secure key for session management
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True if using HTTPS (for ngrok, False is fine)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Ensure cross-site cookies work correctly
app.config['SESSION_PERMANENT'] = False  # Session should not be permanent
app.config['SESSION_TYPE'] = 'filesystem'  # Ensures the session is saved on the server side

# Twitter OAuth URLs
AUTHORIZATION_BASE_URL = "https://twitter.com/i/oauth2/authorize"
TOKEN_URL = "https://api.twitter.com/2/oauth2/token"

# Function to generate code_verifier and code_challenge
def generate_code_verifier_and_challenge():
    code_verifier = secrets.token_urlsafe(128)  # Random string for code_verifier
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")  # SHA256 for code_challenge
    return code_verifier, code_challenge

@app.route("/")
def home():
    return "Welcome to the Twitter OAuth 2.0 Demo"

@app.route("/login")
def login():
    # Generate code_verifier and code_challenge
    code_verifier, code_challenge = generate_code_verifier_and_challenge()

    # Store the code_verifier and state in session to use later
    session["code_verifier"] = code_verifier
    state = secrets.token_urlsafe(16)  # Generate a random state for CSRF protection
    session["state"] = state

    # Debugging print to check values
    print(f"State set in session: {session['state']}")
    print(f"Generated state: {state}")
    print(f"Generated code_verifier: {code_verifier}")

    # Step 1: Redirect the user to Twitter for authorization
    auth_url = (
        f"{AUTHORIZATION_BASE_URL}?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={CALLBACK_URL}"  # Use the CALLBACK_URL from .env
        f"&scope=tweet.read tweet.write users.read"
        f"&state={state}"  # Include the state parameter here
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )
    return redirect(auth_url)

@app.route("/callback")
def callback():
    # Step 2: Handle the callback from Twitter
    received_state = request.args.get("state")
    expected_state = session.get("state")

    # Debugging print to check state values
    print(f"Expected State: {expected_state}, Received State: {received_state}")

    # Ensure the state matches what we sent earlier
    if not received_state or received_state != expected_state:
        return f"Error: State mismatch. Expected: {expected_state}, Received: {received_state}", 400

    authorization_code = request.args.get("code")
    if not authorization_code:
        return "Authorization failed.", 400

    # Retrieve the code_verifier from the session
    code_verifier = session.get("code_verifier")
    if not code_verifier:
        return "Error: Missing code_verifier", 400

    # Step 3: Exchange the authorization code for an access token
    token_response = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "redirect_uri": CALLBACK_URL,  # Use the CALLBACK_URL from .env
            "code": authorization_code,
            "code_verifier": code_verifier,
        },
        auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET),
    )

    # Check if the request was successful
    if token_response.status_code != 200:
        return f"Failed to obtain access token: {token_response.status_code}, {token_response.text}", 400

    # Extract access token from response
    token_data = token_response.json()
    access_token = token_data.get("access_token")
    session["access_token"] = access_token

    return redirect(url_for("profile"))

@app.route("/profile")
def profile():
    # Step 4: Use the access token to access the Twitter API
    access_token = session.get("access_token")
    if not access_token:
        return redirect(url_for("login"))

    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get("https://api.twitter.com/2/users/me", headers=headers)

    if response.status_code != 200:
        return f"Failed to fetch user data: {response.json()}", 400

    user_info = response.json()
    return render_template_string("<h1>User Profile</h1><pre>{{ user_info }}</pre>", user_info=user_info)

@app.route("/status")
def status():
    # A simple status check route to ensure that the app is working as expected
    return "App is working fine! Access granted and authorized."

if __name__ == "__main__":
    app.run(debug=True, port=3000)