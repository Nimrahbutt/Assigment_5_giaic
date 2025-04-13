# 🔐 Develop a Streamlit-based secure data storage and retrieval system
# Instructor & Developer: Nimrah Butt 💻✨

import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode, urlsafe_b64decode
from hashlib import pbkdf2_hmac

# === User data constants ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# === Session states ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === Helper Functions ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# === Load stored data ===
stored_data = load_data()

# === UI ===
st.title("🔐 Secure Data Encryption System")
st.markdown("**👩‍💻 Created by Nimrah Butt** — a simple, secure data encryption app using Streamlit, Python, and 💡 cryptography!")

menu = ["🏠 Home", "📝 Register", "🔑 Login", "💾 Store Data", "🔍 Retrieve Data"]
choice = st.sidebar.selectbox("📌 Navigation", menu)

# === Home ===
if choice == "🏠 Home":
    st.subheader("✨ Welcome to the Secure Data Encryption System!")
    st.markdown("""
    🔐 Store sensitive data securely with encryption.<br>
    🔑 Retrieve it using your secret passkey.<br>
    🚫 Too many failed login attempts? You're locked out temporarily.<br>
    📦 No external database — it's all file-based and secure!  
    """, unsafe_allow_html=True)

# === Register ===
elif choice == "📝 Register":
    st.subheader("🆕 Register New User")
    username = st.text_input("👤 Choose a username")
    password = st.text_input("🔒 Choose a password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("🚫 Both fields are required.")

# === Login ===
elif choice == "🔑 Login":
    st.subheader("🔐 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"🚫 Too many attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"🎉 Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! Attempts left: {remaining}")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🚨 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# === Store Data ===
elif choice == "💾 Store Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please log in first.")
    else:
        st.subheader("🔐 Store Encrypted Data")
        data = st.text_input("📝 Enter data to encrypt")
        passkey = st.text_input("🔑 Encryption key (passphrase)", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("🚫 All fields must be filled.")

# === Retrieve Data ===
elif choice == "🔍 Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please log in first.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("📭 No data found.")
        else:
            st.write("🔐 Encrypted Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("📋 Enter Encrypted Text")
            passkey = st.text_input("🔑 Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"🔓 Decrypted Text: {result}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")

# === Footer ===
st.markdown("---")
st.markdown("✨ Developed with ❤️ by **[Nimrah Butt](https://github.com/)** — your friendly Streamlit dev! 🚀")
