import os
from flask import Flask, redirect, request, session, render_template_string
import requests
import json
import random
import string
import logging
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# Environment variables for configuration
app.secret_key = os.getenv('FLASK_SECRET_KEY')  # Required

# Fortigate configuration
FORITGATE_IP = os.getenv('FORITGATE_IP')  # Required
FORTIGATE_API_KEY = os.getenv('FORTIGATE_API_KEY')  # Required
FORTIGATE_API_URL = f'https://{FORITGATE_IP}/api/v2/cmdb/firewall/address/'
FORTIGATE_CAPTIVE_URL = os.getenv('FORIGATE_CAPTIVE_URL')  # Required

# Discord configuration
DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')  # Required
DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')  # Required
DISCORD_REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI')  # Required
DISCORD_GUILD_ID = os.getenv('DISCORD_GUILD_ID')  # Required
DISCORD_AUTH_URL = "https://discord.com/api/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_USER_URL = 'https://discord.com/api/users/@me'
DISCORD_GUILDS_URL = "https://discord.com/api/users/@me/guilds"
DISCORD_INVITE_URL = os.getenv('DISCORD_INVITE_URL')  # Required


# Other configuration
PORT = os.getenv('FLASK_RUN_PORT', 80)  # Optional

# Validate required environment variables
required_env_vars = [
    'FLASK_SECRET_KEY',
    'FORITGATE_IP',
    'FORTIGATE_API_KEY',
    'DISCORD_CLIENT_ID',
    'DISCORD_CLIENT_SECRET',
    'DISCORD_REDIRECT_URI',
    'DISCORD_GUILD_ID'
]

for var in required_env_vars:
    if os.getenv(var) is None:
        raise ValueError(f"Environment variable {var} is required but not set.")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

executor = ThreadPoolExecutor()

def generate_random_string(length=5):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def create_fortigate_object(address_payload, headers):
    logging.info("Starting Fortigate object creation.")
    try:
        response = requests.post(FORTIGATE_API_URL, headers=headers, data=json.dumps(address_payload), verify=False)
        if response.status_code == 200:
            logging.info("Address object created successfully.")
        else:
            logging.error(f"Failed to create address object. Status Code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        logging.error(f"Error while creating Fortigate object: {str(e)}")

def is_member_of_guild(access_token):
    """Check if the user is a member of the specified Discord Guild."""
    guilds_url = DISCORD_GUILDS_URL
    headers = {"Authorization": f"Bearer {access_token}"}
    
    try:
        guilds_response = requests.get(guilds_url, headers=headers)
        if guilds_response.status_code == 200:
            guilds = guilds_response.json()
            for guild in guilds:
                if guild['id'] == DISCORD_GUILD_ID:
                    return True
        else:
            logging.error(f"Failed to fetch guilds. Status Code: {guilds_response.status_code}")
    except Exception as e:
        logging.error(f"Error checking guild membership: {str(e)}")
    return False

@app.route("/login")
def login():
    original_uri = request.args.get('uri')
    magic = request.args.get('session')
    session['original_uri'] = original_uri
    session['magic'] = magic
    discord_login_url = f"{DISCORD_AUTH_URL}?client_id={DISCORD_CLIENT_ID}&redirect_uri={DISCORD_REDIRECT_URI}&response_type=code&scope=identify guilds"
    logging.info(f"Redirecting to Discord OAuth: {discord_login_url}")
    return redirect(discord_login_url)

@app.route("/callback")
def callback():
    code = request.args.get('code')
    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI
    }
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    print(DISCORD_TOKEN_URL)
    token_response = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers)
    access_token = token_response.json().get('access_token')
    
    user_headers = {"Authorization": f"Bearer {access_token}"}
    user_response = requests.get(DISCORD_USER_URL, headers=user_headers)
    username = user_response.json().get('username')

    random_string = generate_random_string()
    object_name = f"{username}-{random_string}"

    user_ip = request.remote_addr
    original_uri = session.get('original_uri')
    magic = session.get('magic')

    # Check if the user is a member of the Discord guild
    if not is_member_of_guild(access_token):
        logging.info(f"User {username} is not a member of the guild. Redirecting to Discord invite.")
        original_uri = DISCORD_INVITE_URL  # Change the original URI to Discord invite if not a member

    address_payload = {
        "name": object_name,
        "subnet": f"{user_ip} 255.255.255.255",
        "type": "ipmask",
        "comment": f"User: {username} - IP: {user_ip}"
    }

    fortigate_headers = {
        'Authorization': f'Bearer {FORTIGATE_API_KEY}',
        'Content-Type': 'application/json'
    }

    # Run the Fortigate object creation in a background thread
    executor.submit(create_fortigate_object, address_payload, fortigate_headers)

    return render_template_string("""
    <html>
    <head>
        <title>Redirecting...</title>
    </head>
    <body>
        <form id="fortigate_form" action="{{ FORTIGATE_CAPTIVE_URL }}" method="POST">
            <input type="hidden" name="4Tredir" value="{{ original_uri }}">
            <input type="hidden" name="magic" value="{{ magic }}">
            <input type="hidden" name="answer" value="1">
            <input type="hidden" name="username" value="{{ username }}">
        </form>
        <script type="text/javascript">
            document.getElementById('fortigate_form').submit();
        </script>
        <p>Redirecting to FortiGate...</p>
    </body>
    </html>
    """, FORTIGATE_CAPTIVE_URL=FORTIGATE_CAPTIVE_URL, original_uri=original_uri, magic=magic, username=username)

@app.route("/skip")
def skip():
    original_uri = request.args.get('uri')
    magic = request.args.get('session')
    return render_template_string("""
        <html>
        <head>
            <title>Redirecting...</title>
        </head>
        <body>
            <form id="fortigate_form" action="{{ FORTIGATE_CAPTIVE_URL }}" method="POST">
                <input type="hidden" name="4Tredir" value="{{ original_uri }}">
                <input type="hidden" name="magic" value="{{ magic }}">
                <input type="hidden" name="answer" value="1">
                <input type="hidden" name="username" value="{{ username }}">
            </form>
            <script type="text/javascript">
                document.getElementById('fortigate_form').submit();
            </script>
            <p>Redirecting to FortiGate...</p>
        </body>
        </html>
    """, FORTIGATE_CAPTIVE_URL=FORTIGATE_CAPTIVE_URL, original_uri=original_uri, magic=magic)

@app.route("/check")
def check():
    return "", 200


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=PORT)
