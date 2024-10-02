import streamlit as st
import requests
import msal

# Constants for Microsoft OAuth2
CLIENT_ID = '0be58899-7c38-4e10-8fb3-b71c9ef3705e'
CLIENT_SECRET = 'hL_8Q~7QyRCeUIx_D2~0eusgrWrkp40UZJleocGz'
TENANT_ID = 'f854fda6-184f-4f40-a5e2-83a4f8924a15'
AUTHORITY = f'https://login.microsoftonline.com/{TENANT_ID}'
REDIRECT_URI = 'https://fabricartifacts.streamlit.app/'
SCOPE = ['User.Read']  # You can add more scopes based on the permissions your app needs
FABRIC_API_SCOPE = ['https://management.azure.com/.default']

# --- Function to create an MSAL Confidential Client App ---
def create_msal_app():
    return msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET
    )

# --- Function to authenticate and get a token from Microsoft ---
def authenticate_with_microsoft():
    msal_app = create_msal_app()

    # Build the auth URL
    auth_url = msal_app.get_authorization_request_url(SCOPE, redirect_uri=REDIRECT_URI)
    
    # Open the authorization URL in the browser
    st.write(f"[Login with Microsoft]({auth_url})")

    auth_code = st.text_input("Enter the authorization code after login")
    
    if st.button("Get Access Token"):
        if auth_code:
            result = msal_app.acquire_token_by_authorization_code(
                auth_code,
                scopes=SCOPE,
                redirect_uri=REDIRECT_URI
            )

            if "access_token" in result:
                st.session_state['oauth_token'] = result['access_token']
                st.success("Login successful")
            else:
                st.error(f"Failed to get token: {result.get('error_description')}")
        else:
            st.error("Authorization code is required.")

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

    # Microsoft OAuth login option
    if st.button("Login with Microsoft OAuth"):
        authenticate_with_microsoft()

# --- Welcome screen with side menu ---
def welcome_screen():
    st.sidebar.title("Navigation")
    option = st.sidebar.radio("Select an option", ["Home", "Settings", "Logout"])

    if option == "Home":
        st.title("Fabric Accelerator")
        st.write("Welcome to Fabric Accelerator")
        
        if st.session_state['oauth_token']:
            st.write("You are logged in with Microsoft OAuth.")
        else:
            st.write("You are not authenticated via OAuth.")

        domain = st.text_input("Domain")
        artifact = st.text_input("Artifact")
        workspace = st.text_input("Workspace")
        
        if st.button("Call Fabric API"):
            if st.session_state['oauth_token']:
                status, response = call_fabric_api_oauth(domain, artifact, workspace, st.session_state['oauth_token'])
            else:
                st.error("Please authenticate via Microsoft OAuth first.")
                return

            if status == "Success":
                st.success(f"API call successful: {response}")
            else:
                st.error(f"API call failed: {response}")

    elif option == "Settings":
        st.title("Settings")
        st.write("Here you can adjust settings.")

    elif option == "Logout":
        st.session_state['logged_in'] = False
        st.session_state['oauth_token'] = None
        st.success("You have been logged out")

# --- Run the main app ---
if __name__ == "__main__":
    main()
