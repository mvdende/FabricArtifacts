import streamlit as st
import requests
from urllib.parse import urlencode
import webbrowser
import json

# Constants for OAuth2
CLIENT_ID = 'bd1de6bb-61a9-4f73-afb4-315ef30dc260'
CLIENT_SECRET = 'hL_8Q~7QyRCeUIx_D2~0eusgrWrkp40UZJleocGz'
AUTH_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
TOKEN_URL = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
REDIRECT_URI = 'http://localhost:8501'
SCOPE = ['https://management.azure.com/.default']

# --- Function to authenticate with Microsoft OAuth ---
def authenticate_with_oauth():
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'response_mode': 'query',
        'scope': ' '.join(SCOPE),
        'state': '12345'
    }
    auth_request_url = f"{AUTH_URL}?{urlencode(params)}"
    
    # Open the authentication page
    webbrowser.open(auth_request_url)

# --- Function to exchange code for token ---
def get_token(auth_code):
    data = {
        'client_id': CLIENT_ID,
        'scope': ' '.join(SCOPE),
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
        'client_secret': CLIENT_SECRET
    }
    response = requests.post(TOKEN_URL, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        st.error(f"Failed to get token: {response.text}")
        return None

# --- Function to call Microsoft Fabric REST API with OAuth token ---
def call_fabric_api_oauth(domain, artifact, workspace, access_token):
    url = f"https://fabric-api-url.com/api/v1/{workspace}/artifacts"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    payload = {
        'domain': domain,
        'artifact': artifact
    }
    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 200:
        return "Success", response.json()
    else:
        return "Error", response.text

# --- Main app logic ---
def main():
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
    if 'oauth_token' not in st.session_state:
        st.session_state['oauth_token'] = None
    
    if not st.session_state['logged_in']:
        login()
    else:
        welcome_screen()

# --- Login screen ---
def login():
    st.title("Login to Fabric Accelerator")
    
    # Normal login option
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if authenticate(username, password):
            st.session_state['logged_in'] = True
            st.success("Login successful")
            welcome_screen()
        else:
            st.error("Invalid username or password")
    
    # OAuth login option
    if st.button("Login with Microsoft OAuth"):
        authenticate_with_oauth()
        st.write("Please complete OAuth login in the browser.")

# --- Welcome screen with side menu ---
def welcome_screen():
    st.sidebar.title("Navigation")
    option = st.sidebar.radio("Select an option", ["Home", "Settings", "Logout", "OAuth Authentication"])

    if option == "Home":
        st.title("Fabric Accelerator")
        st.write("Welcome to Fabric Accelerator")
        
        if st.session_state['oauth_token']:
            st.write("You are logged in with OAuth.")
        else:
            st.write("You are not authenticated via OAuth.")

        domain = st.text_input("Domain")
        artifact = st.text_input("Artifact")
        workspace = st.text_input("Workspace")
        
        if st.button("Call Fabric API"):
            if st.session_state['oauth_token']:
                status, response = call_fabric_api_oauth(domain, artifact, workspace, st.session_state['oauth_token']['access_token'])
            else:
                st.error("Please authenticate via OAuth first.")
                return

            if status == "Success":
                st.success(f"API call successful: {response}")
            else:
                st.error(f"API call failed: {response}")
    
    elif option == "OAuth Authentication":
        oauth_authentication_screen()
    
    elif option == "Settings":
        st.title("Settings")
        st.write("Here you can adjust settings.")

    elif option == "Logout":
        st.session_state['logged_in'] = False
        st.session_state['oauth_token'] = None
        st.success("You have been logged out")

# --- OAuth Authentication screen ---
def oauth_authentication_screen():
    st.title("OAuth Authentication")
    
    auth_code = st.text_input("Enter the authorization code")
    
    if st.button("Get Access Token"):
        token = get_token(auth_code)
        if token:
            st.session_state['oauth_token'] = token
            st.success("OAuth token obtained successfully")
        else:
            st.error("Failed to obtain OAuth token")

# --- Function to authenticate username/password (basic) ---
def authenticate(username, password):
    # Simple authentication logic
    if username == "admin" and password == "password":
        return True
    else:
        return False

if __name__ == "__main__":
    main()
