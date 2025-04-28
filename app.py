#Import libararies for web app and api request
from flask import Flask, request, jsonify, render_template
import requests
import time
import socket 
from urllib.parse import urlparse

app = Flask(__name__)

# Setup google safe browsing api endpoint with API key
# The API will be used to send URLs for threat analysis
API_KEY = "AIzaSyAZkeR_u23UXX1IjSVXf3y9a81xAfHzL1U"
API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"


# Loads the homepage UI from index.html
# this is where users paste URLs to check
@app.route("/")
def home():
    return render_template("index.html")

# POST endpoint that takes URL and checks through google safe browsing
@app.route("/scan", methods=["POST"])
def scan():
    time.sleep(1.5) #just to show scan msg
    data = request.json
    url = data.get("url", "")

# Parse and extract domain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path  # handle if scheme missing

    if not domain:
        return jsonify({"error": "Invalid URL format."}), 400

    # DNS check - Does domain exist?
    try:
        socket.gethostbyname(domain)
    except socket.error:
        return jsonify({ "error": "This domain does not exist." }), 200

    # did the user send something?
    if not url:
        return jsonify({"error": "No URL provided."}), 400

    # Payload to send to google API
    # Format per their spec: types of threats, platforms..
    payload = {
        "client": {
            "clientId": "SafeQR-flask-app",  
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        # Send request to google
        response = requests.post(API_URL, json=payload)
        response.raise_for_status()
        result = response.json()
        
    except requests.RequestException as e:
        return jsonify({
            "error": "Failed to connect to Google Safe Browsing API",
            "details": str(e)
        }), 502

    # Analyse response, return verdict
    if result.get("matches"):
        return jsonify({
            "is_malicious": True,
            "message": "❌ This URL is malicious! ❌"
        })
    else:
        return jsonify({
            "is_malicious": False,
            "message": "✅ This URL is safe. ✅ "
        })


# Runs app in debug mode when file executed directly
if __name__ == "__main__":
    app.run()
