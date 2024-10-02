import streamlit as st
import requests

# --- Function to authenticate user ---
def authenticate(username, password):
    # Simple authentication logic
    if username == "admin" and password == "password":
        return True
    else:
        return False

# --- Function to call Microsoft Fabric REST API ---
def call_fabric_api(domain, artifact, workspace):
    url = f"https://fabric-api-url.com/api/v1/{workspace}/artifacts"
    headers = {
        'Authorization': 'Bearer your_token_here',  # Include necessary auth token
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
    
    if not st.session_state['logged_in']:
        login()
    else:
        welcome_screen()

# --- Login screen ---
def login():
    st.title("Login to Fabric Accelerator")
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if authenticate(username, password):
            st.session_state['logged_in'] = True
            st.success("Login successful")
            welcome_screen()
        else:
            st.error("Invalid username or password")

# --- Welcome screen with side menu ---
def welcome_screen():
    st.sidebar.title("Navigation")
    option = st.sidebar.radio("Select an option", ["Home", "Settings", "Logout"])

    if option == "Home":
        st.title("Fabric Accelerator")
        st.write("Welcome to Fabric Accelerator")
        
        domain = st.text_input("Domain")
        artifact = st.text_input("Artifact")
        workspace = st.text_input("Workspace")
        
        if st.button("Call Fabric API"):
            status, response = call_fabric_api(domain, artifact, workspace)
            if status == "Success":
                st.success(f"API call successful: {response}")
            else:
                st.error(f"API call failed: {response}")

    elif option == "Settings":
        st.title("Settings")
        st.write("Here you can adjust settings.")

    elif option == "Logout":
        st.session_state['logged_in'] = False
        st.success("You have been logged out")

if __name__ == "__main__":
    main()

