import streamlit as st
import pandas as pd
import csv
import os
import uuid
import datetime
import tempfile
import hashlib
import qrcode
from qrcode.constants import ERROR_CORRECT_H
from werkzeug.security import generate_password_hash, check_password_hash
import re
from PIL import Image
import base64

# Configuration
DATA_DIR = "data"
QR_DIR = os.path.join("static", "qr")
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
ACCOUNTS_CSV = os.path.join(DATA_DIR, "accounts.csv")
TXNS_CSV = os.path.join(DATA_DIR, "transactions.csv")
PINS_CSV = os.path.join(DATA_DIR, "pins.csv")

# Page config
st.set_page_config(
    page_title="Mini Bank",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize directories and CSV files
@st.cache_data
def init_files():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(QR_DIR, exist_ok=True)
    
    if not os.path.exists(USERS_CSV):
        with open(USERS_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["user_id", "username", "email", "password_hash"])
    
    if not os.path.exists(ACCOUNTS_CSV):
        with open(ACCOUNTS_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["user_id", "account_no", "balance"])
    
    if not os.path.exists(TXNS_CSV):
        with open(TXNS_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["tx_id", "account_no", "type", "amount", "date", "desc"])
    
    if not os.path.exists(PINS_CSV):
        with open(PINS_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["user_id", "pin_hash"])

# Custom CSS
def load_css():
    st.markdown("""
    <style>
        .main-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .balance-card {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            color: white;
            padding: 2rem;
            border-radius: 15px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .success-message {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 1rem;
            border-radius: 5px;
            margin: 1rem 0;
        }
        
        .error-message {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 1rem;
            border-radius: 5px;
            margin: 1rem 0;
        }
        
        .warning-message {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 1rem;
            border-radius: 5px;
            margin: 1rem 0;
        }
        
        .pin-required-banner {
            background: linear-gradient(135deg, #ff6b6b, #ffa500);
            color: white;
            padding: 1.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            text-align: center;
        }
        
        .feature-box {
            background: black;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 1rem;
        }
    </style>
    """, unsafe_allow_html=True)

# PIN helper functions
def hash_pin(pin):
    salt = "mini_bank_pin_salt_2024"
    return hashlib.sha256(f"{pin}{salt}".encode()).hexdigest()

def verify_pin(pin, pin_hash):
    return hash_pin(pin) == pin_hash

def set_user_pin(user_id, pin):
    pin_hash = hash_pin(pin)
    pins = read_csv(PINS_CSV)
    
    existing = False
    for i, p in enumerate(pins):
        if p["user_id"] == user_id:
            pins[i]["pin_hash"] = pin_hash
            existing = True
            break
    
    if existing:
        write_csv_atomic(PINS_CSV, ["user_id", "pin_hash"], pins)
    else:
        append_csv(PINS_CSV, ["user_id", "pin_hash"], {
            "user_id": user_id,
            "pin_hash": pin_hash
        })

def get_user_pin_hash(user_id):
    pins = read_csv(PINS_CSV)
    for p in pins:
        if p["user_id"] == user_id:
            return p["pin_hash"]
    return None

def user_has_pin(user_id):
    return get_user_pin_hash(user_id) is not None

def verify_user_pin(user_id, pin):
    pin_hash = get_user_pin_hash(user_id)
    if not pin_hash:
        return False
    return verify_pin(pin, pin_hash)

# CSV helper functions
def read_csv(path):
    rows = []
    if not os.path.exists(path):
        return rows
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                rows.append(r)
    except Exception as e:
        st.error(f"Error reading {path}: {e}")
    return rows

def append_csv(path, fieldnames, rowdict):
    try:
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if os.stat(path).st_size == 0:
                writer.writeheader()
            writer.writerow(rowdict)
    except Exception as e:
        st.error(f"Error writing to {path}: {e}")

def write_csv_atomic(path, fieldnames, rows):
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
        os.replace(tmp, path)
    except Exception as e:
        st.error(f"Error updating {path}: {e}")

# Business logic functions
def find_user_by_email(email):
    for u in read_csv(USERS_CSV):
        if u["email"].lower() == email.lower():
            return u
    return None

def find_user_by_id(user_id):
    for u in read_csv(USERS_CSV):
        if u["user_id"] == user_id:
            return u
    return None

def find_user_by_account(account_no):
    accounts = read_csv(ACCOUNTS_CSV)
    match = next((a for a in accounts if a["account_no"] == account_no), None)
    if not match:
        return None
    return find_user_by_id(match["user_id"])

def create_account_for_user(user_id, initial_balance=0.0):
    account_no = str(1000000000 + int(uuid.uuid4().int % 899999999))
    append_csv(ACCOUNTS_CSV, ["user_id", "account_no", "balance"], {
        "user_id": user_id,
        "account_no": account_no,
        "balance": f"{float(initial_balance):.2f}"
    })
    return account_no

def get_account_by_user(user_id):
    accounts = [a for a in read_csv(ACCOUNTS_CSV) if a["user_id"] == user_id]
    return accounts[0] if accounts else None

def get_account_by_accountno(account_no):
    accounts = [a for a in read_csv(ACCOUNTS_CSV) if a["account_no"] == account_no]
    return accounts[0] if accounts else None

def update_account_balance(account_no, new_balance):
    rows = read_csv(ACCOUNTS_CSV)
    for r in rows:
        if r["account_no"] == account_no:
            r["balance"] = f"{float(new_balance):.2f}"
    write_csv_atomic(ACCOUNTS_CSV, ["user_id","account_no","balance"], rows)

def add_transaction(account_no, ttype, amount, desc=""):
    append_csv(TXNS_CSV, ["tx_id","account_no","type","amount","date","desc"], {
        "tx_id": str(uuid.uuid4()),
        "account_no": account_no,
        "type": ttype,
        "amount": f"{float(amount):.2f}",
        "date": datetime.datetime.utcnow().isoformat(),
        "desc": desc
    })

def get_transactions_for_account(account_no, limit=100):
    rows = [t for t in read_csv(TXNS_CSV) if t["account_no"] == account_no]
    rows.sort(key=lambda r: r["date"], reverse=True)
    return rows[:limit]

# Password validation
def is_password_strong(pw: str) -> bool:
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$'
    return bool(re.match(pattern, pw))

def is_pin_valid(pin: str) -> bool:
    return bool(re.match(r'^\d{4}$', pin))

# QR Code generation
def generate_qr_for_account(account_no, data=None):
    try:
        qr_path = os.path.join(QR_DIR, f"{account_no}.png")
        payload = data or f"account:{account_no}"
        qr = qrcode.QRCode(
            version=4,
            error_correction=ERROR_CORRECT_H,
            box_size=8,
            border=2,
        )
        qr.add_data(payload)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(qr_path)
        return qr_path
    except Exception as e:
        st.error(f"Error generating QR code: {e}")
        return None

def get_qr_image(account_no):
    qr_path = os.path.join(QR_DIR, f"{account_no}.png")
    if os.path.exists(qr_path):
        return qr_path
    return None

# Initialize session state
def init_session_state():
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'current_user' not in st.session_state:
        st.session_state.current_user = None
    if 'page' not in st.session_state:
        st.session_state.page = 'home'
    if 'show_pin_modal' not in st.session_state:
        st.session_state.show_pin_modal = False

# Authentication functions
def login_user(email_or_account, password):
    user = None
    
    if email_or_account.isdigit() and len(email_or_account) == 10:
        user = find_user_by_account(email_or_account)
    else:
        user = find_user_by_email(email_or_account)
    
    if user and check_password_hash(user["password_hash"], password):
        st.session_state.logged_in = True
        st.session_state.current_user = user
        return True
    return False

def logout_user():
    st.session_state.logged_in = False
    st.session_state.current_user = None
    st.session_state.page = 'home'
    st.session_state.show_pin_modal = False

def register_user(username, email, password, initial_deposit=0.0):
    if find_user_by_email(email):
        return False, "Email already registered"
    
    if not is_password_strong(password):
        return False, "Password does not meet strength requirements"
    
    user_id = str(uuid.uuid4())
    pw_hash = generate_password_hash(password)
    
    append_csv(USERS_CSV, ["user_id","username","email","password_hash"], {
        "user_id": user_id,
        "username": username,
        "email": email,
        "password_hash": pw_hash
    })
    
    account_no = create_account_for_user(user_id, initial_balance=initial_deposit)
    if float(initial_deposit) > 0:
        add_transaction(account_no, "deposit", initial_deposit, "Initial deposit")
    
    generate_qr_for_account(account_no, data=f"user:{username}|email:{email}|account:{account_no}")
    
    return True, "Registration successful"

def delete_user_data(user_id, account_no):
    """Delete all user data from CSV files and remove QR code file"""
    try:
        # Delete from users.csv
        users = read_csv(USERS_CSV)
        users = [u for u in users if u["user_id"] != user_id]
        write_csv_atomic(USERS_CSV, ["user_id", "username", "email", "password_hash"], users)
        
        # Delete from accounts.csv
        accounts = read_csv(ACCOUNTS_CSV)
        accounts = [a for a in accounts if a["user_id"] != user_id]
        write_csv_atomic(ACCOUNTS_CSV, ["user_id", "account_no", "balance"], accounts)
        
        # Delete from pins.csv
        pins = read_csv(PINS_CSV)
        pins = [p for p in pins if p["user_id"] != user_id]
        write_csv_atomic(PINS_CSV, ["user_id", "pin_hash"], pins)
        
        # Delete from transactions.csv
        if account_no:
            transactions = read_csv(TXNS_CSV)
            transactions = [t for t in transactions if t["account_no"] != account_no]
            write_csv_atomic(TXNS_CSV, ["tx_id", "account_no", "type", "amount", "date", "desc"], transactions)
            
            # Delete QR code file if it exists
            qr_file = os.path.join(QR_DIR, f"{account_no}.png")
            if os.path.exists(qr_file):
                try:
                    os.remove(qr_file)
                except OSError:
                    pass
    except Exception as e:
        st.error(f"Error deleting user data: {e}")

# Page functions
def show_home():
    st.markdown("""
    <div class="main-header">
        <h1>🏦 Welcome to Mini Bank</h1>
        <p>Experience the future of banking with our modern, secure, and intuitive platform</p>
    </div>
    """, unsafe_allow_html=True)
    
    if not st.session_state.logged_in:
        st.subheader("🌟 Features")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            <div class="feature-box">
                <h4>🔐 Bank-Grade Security</h4>
                <p>Your data is protected with industry-standard encryption and secure password hashing.</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="feature-box">
                <h4>⚡ Lightning Fast</h4>
                <p>Real-time transactions and balance updates with optimized performance.</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="feature-box">
                <h4>📈 Transaction History</h4>
                <p>Track all your financial activities with detailed transaction logs.</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="feature-box">
                <h4>📱 QR Code Integration</h4>
                <p>Generate and share account details instantly with high-quality QR codes.</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="feature-box">
                <h4>💳 Smart Transactions</h4>
                <p>Deposit, withdraw, and transfer with intelligent validation and PIN security.</p>
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown("""
            <div class="feature-box">
                <h4>🎨 Modern Design</h4>
                <p>Beautiful, responsive interface designed for both desktop and mobile.</p>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success(f"Welcome back, {st.session_state.current_user['username']}!")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📊 Go to Dashboard", use_container_width=True, key="home_dashboard"):
                st.session_state.page = 'dashboard'
                st.rerun()
        with col2:
            if st.button("🚪 Logout", use_container_width=True, key="home_logout"):
                logout_user()
                st.rerun()

def show_login():
    st.markdown("## 🔑 Welcome Back")
    
    with st.form("login_form"):
        st.write("Sign in with your **email** or **10-digit account number**")
        
        email_or_account = st.text_input("📧 Email or 🏦 Account Number")
        password = st.text_input("🔐 Password", type="password")
        
        submitted = st.form_submit_button("🚀 Sign In", use_container_width=True)
        
        if submitted:
            if not email_or_account or not password:
                st.error("Please provide email/account number and password")
            elif login_user(email_or_account, password):
                st.success(f"Welcome back, {st.session_state.current_user['username']}!")
                st.session_state.page = 'dashboard'
                st.rerun()
            else:
                st.error("Invalid credentials")
    
    st.markdown("---")
    if st.button("✨ Create New Account", use_container_width=True, key="login_signup"):
        st.session_state.page = 'signup'
        st.rerun()

def show_signup():
    st.markdown("## ✨ Join Mini Bank")
    
    with st.form("signup_form"):
        st.write("Create your account in just a few steps")
        
        username = st.text_input("👤 Full Name")
        email = st.text_input("📧 Email Address")
        password = st.text_input("🔐 Create Password", type="password")
        initial_deposit = st.number_input("💰 Initial Deposit (Optional)", min_value=0.0, value=0.0, step=0.01)
        
        st.markdown("""
        **🛡️ Password Security Requirements:**
        - ✅ At least 8 characters long
        - ✅ Include uppercase and lowercase letters
        - ✅ Contains at least one digit (0-9)
        - ✅ Has at least one special character (!@#$%^&*)
        """)
        
        submitted = st.form_submit_button("🚀 Create Account", use_container_width=True)
        
        if submitted:
            if not username or not email or not password:
                st.error("Please fill in all required fields")
            else:
                success, message = register_user(username, email, password, initial_deposit)
                if success:
                    st.success("Account created successfully! Please login.")
                    st.session_state.page = 'login'
                    st.rerun()
                else:
                    st.error(message)
    
    st.markdown("---")
    if st.button("🔑 Already have an account?", use_container_width=True, key="signup_login"):
        st.session_state.page = 'login'
        st.rerun()

def show_dashboard():
    user = st.session_state.current_user
    account = get_account_by_user(user["user_id"])
    
    if not account:
        account_no = create_account_for_user(user["user_id"], initial_balance=0.0)
        account = get_account_by_user(user["user_id"])
    
    has_pin = user_has_pin(user["user_id"])
    
    # Header
    st.markdown(f"""
    <div class="main-header">
        <h1>👋 Welcome, {user['username']}</h1>
        <p>Manage your account and transactions</p>
    </div>
    """, unsafe_allow_html=True)
    
    # PIN Warning Banner
    if not has_pin:
        st.markdown("""
        <div class="pin-required-banner">
            <h3>🔐 Security Setup Required</h3>
            <p>To protect your account and enable transactions, please set up your 4-digit PIN.</p>
            <p><strong>🚫 All transactions are disabled until PIN is set</strong></p>
        </div>
        """, unsafe_allow_html=True)
    
    # Layout
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Account Information
        st.markdown(f"""
        <div class="balance-card">
            <h3>💳 Your Account</h3>
            <p>Account Number: <strong>{account['account_no']}</strong></p>
            <h2>💰 ₹ {float(account['balance']):.2f}</h2>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Transaction Forms
        if has_pin:
            st.subheader("💸 Quick Transactions")
            
            tab1, tab2, tab3 = st.tabs(["💰 Deposit", "💸 Withdraw", "🔄 Transfer"])
            
            with tab1:
                with st.form("deposit_form"):
                    d_amount = st.number_input("Deposit Amount", min_value=0.01, step=0.01, key="deposit_amount")
                    d_desc = st.text_input("Description (optional)", key="deposit_desc")
                    d_pin = st.text_input("Enter 4-digit PIN", type="password", max_chars=4, key="deposit_pin")
                    
                    if st.form_submit_button("💰 Deposit", use_container_width=True):
                        if not is_pin_valid(d_pin):
                            st.error("PIN must be exactly 4 digits")
                        elif not verify_user_pin(user["user_id"], d_pin):
                            st.error("Invalid PIN. Transaction cancelled for security.")
                        else:
                            new_balance = float(account["balance"]) + d_amount
                            update_account_balance(account["account_no"], new_balance)
                            add_transaction(account["account_no"], "deposit", d_amount, d_desc or "Deposit")
                            st.success(f"💰 Deposited ₹{d_amount:.2f} successfully.")
                            st.rerun()
            
            with tab2:
                with st.form("withdraw_form"):
                    w_amount = st.number_input("Withdraw Amount", min_value=0.01, step=0.01, key="withdraw_amount")
                    w_desc = st.text_input("Description (optional)", key="withdraw_desc")
                    w_pin = st.text_input("Enter 4-digit PIN", type="password", max_chars=4, key="withdraw_pin")
                    
                    if st.form_submit_button("💸 Withdraw", use_container_width=True):
                        if not is_pin_valid(w_pin):
                            st.error("PIN must be exactly 4 digits")
                        elif not verify_user_pin(user["user_id"], w_pin):
                            st.error("Invalid PIN. Transaction cancelled for security.")
                        elif float(account["balance"]) < w_amount:
                            st.error("Insufficient funds.")
                        else:
                            new_balance = float(account["balance"]) - w_amount
                            update_account_balance(account["account_no"], new_balance)
                            add_transaction(account["account_no"], "withdraw", w_amount, w_desc or "Withdraw")
                            st.success(f"💸 Withdrawn ₹{w_amount:.2f} successfully.")
                            st.rerun()
            
            with tab3:
                with st.form("transfer_form"):
                    t_account = st.text_input("Target Account (10 digits)", max_chars=10, key="transfer_account")
                    t_amount = st.number_input("Transfer Amount", min_value=0.01, step=0.01, key="transfer_amount")
                    t_pin = st.text_input("Enter 4-digit PIN", type="password", max_chars=4, key="transfer_pin")
                    
                    if st.form_submit_button("🔄 Transfer", use_container_width=True):
                        if not t_account.isdigit() or len(t_account) != 10:
                            st.error("Target account must be exactly 10 digits")
                        elif not is_pin_valid(t_pin):
                            st.error("PIN must be exactly 4 digits")
                        elif not verify_user_pin(user["user_id"], t_pin):
                            st.error("Invalid PIN. Transaction cancelled for security.")
                        elif float(account["balance"]) < t_amount:
                            st.error("Insufficient funds.")
                        else:
                            target_account = get_account_by_accountno(t_account)
                            if not target_account:
                                st.error("Target account not found.")
                            else:
                                # Update balances
                                update_account_balance(account["account_no"], float(account["balance"]) - t_amount)
                                update_account_balance(target_account["account_no"], float(target_account["balance"]) + t_amount)
                                
                                # Add transactions
                                add_transaction(account["account_no"], "transfer_out", t_amount, f"To {t_account}")
                                add_transaction(target_account["account_no"], "transfer_in", t_amount, f"From {account['account_no']}")
                                
                                st.success(f"🔄 Transferred ₹{t_amount:.2f} to {t_account} successfully.")
                                st.rerun()
        else:
            st.markdown("""
            <div class="warning-message">
                <h4>🔒 Security Notice</h4>
                <p>Set up your 4-digit PIN to start making transactions.</p>
                <p><strong>All transaction features are currently disabled for security.</strong></p>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        # QR Code Section
        st.subheader("📱 Your Account QR")
        qr_path = get_qr_image(account["account_no"])
        
        if qr_path:
            try:
                image = Image.open(qr_path)
                st.image(image, caption="Share this QR code for quick account identification", width=200)
            except Exception as e:
                st.error(f"Error loading QR code: {e}")
            
            if st.button("🔄 Regenerate QR", use_container_width=True, key="regen_qr"):
                generate_qr_for_account(account["account_no"], 
                                      data=f"user:{user['username']}|email:{user['email']}|account:{account['account_no']}")
                st.success("QR code regenerated successfully.")
                st.rerun()
        else:
            st.write("No QR code available yet")
            if st.button("✨ Generate QR Code", use_container_width=True, key="gen_qr"):
                generate_qr_for_account(account["account_no"], 
                                      data=f"user:{user['username']}|email:{user['email']}|account:{account['account_no']}")
                st.success("QR code generated successfully.")
                st.rerun()
        
        st.markdown("---")
        
        # PIN Management
        st.subheader("🔐 PIN Security")
        
        if has_pin:
            st.success("✅ PIN is set and active")
            st.write("Your transactions are protected with a 4-digit PIN.")
        else:
            st.warning("⚠️ PIN Required - Transactions Disabled")
            st.markdown("""
            <div class="error-message">
                <p><strong>🚫 All transactions are currently disabled for security.</strong></p>
                <p>Set up your 4-digit PIN to enable deposits, withdrawals, and transfers.</p>
            </div>
            """, unsafe_allow_html=True)
        
        # PIN Setup/Change
        if st.button("🔐 Set PIN" if not has_pin else "🔄 Change PIN", use_container_width=True, key="set_pin_btn"):
            st.session_state.show_pin_modal = True
        
        # PIN Setup Modal
        if st.session_state.show_pin_modal:
            st.markdown("---")
            st.subheader("🔐 Set PIN" if not has_pin else "🔄 Change PIN")
            
            with st.form("pin_setup_form"):
                pin = st.text_input("Enter 4-digit PIN", type="password", max_chars=4, key="new_pin")
                confirm_pin = st.text_input("Confirm PIN", type="password", max_chars=4, key="confirm_pin")
                
                col1, col2 = st.columns(2)
                with col1:
                    cancel_btn = st.form_submit_button("Cancel")
                with col2:
                    submit_btn = st.form_submit_button("Set PIN" if not has_pin else "Update PIN")
                
                # Handle form submission
                if cancel_btn:
                    st.session_state.show_pin_modal = False
                    st.rerun()
                elif submit_btn:
                    if not is_pin_valid(pin):
                        st.error("PIN must be exactly 4 digits.")
                    elif pin != confirm_pin:
                        st.error("PIN and confirmation PIN do not match.")
                    else:
                        set_user_pin(user["user_id"], pin)
                        st.session_state.show_pin_modal = False
                        if has_pin:
                            st.success("PIN updated successfully! Your transactions are now secured with the new PIN.")
                        else:
                            st.success("PIN set successfully! You can now make secure deposits, withdrawals, and transfers.")
                        st.rerun()
    
    st.markdown("---")
    
    # Transaction History
    st.subheader("📊 Recent Transactions")
    txns = get_transactions_for_account(account["account_no"])
    
    if txns:
        # Convert to DataFrame for better display
        df_data = []
        for t in txns:
            try:
                date_str = t['date'].split('T')[0]
                time_str = t['date'].split('T')[1].split('.')[0] if 'T' in t['date'] else t['date']
                
                # Format transaction type
                type_display = {
                    'deposit': '💰 Deposit',
                    'withdraw': '💸 Withdraw', 
                    'transfer_in': '📥 Transfer In',
                    'transfer_out': '📤 Transfer Out'
                }.get(t['type'], t['type'])
                
                df_data.append({
                    'Date': date_str,
                    'Time': time_str,
                    'Type': type_display,
                    'Amount': f"₹ {float(t['amount']):.2f}",
                    'Description': t['desc'] or '-'
                })
            except (ValueError, KeyError) as e:
                continue  # Skip malformed entries
        
        if df_data:
            df = pd.DataFrame(df_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No valid transactions found.")
    else:
        st.info("No transactions yet. " + ("Start by making a deposit or transfer!" if has_pin else "Set your PIN first, then start making transactions!"))
    
    st.markdown("---")
    
    # Account Management
    st.subheader("⚙️ Account Management")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🏠 Home", use_container_width=True, key="dash_home"):
            st.session_state.page = 'home'
            st.rerun()
    
    with col2:
        if st.button("🚪 Logout", use_container_width=True, key="dash_logout"):
            logout_user()
            st.success("Logged out successfully.")
            st.rerun()
    
    # Danger Zone
    with st.expander("⚠️ Danger Zone - Delete Account"):
        st.warning("**Warning**: This action cannot be undone. This will permanently delete your account, remove all transaction history, and delete all associated data.")
        
        if st.checkbox("I understand this action cannot be undone"):
            with st.form("delete_account_form"):
                confirm_text = st.text_input('Type "delete my account" to confirm:')
                password = st.text_input("Enter your password to confirm:", type="password")
                
                if st.form_submit_button("🗑️ Delete Account Permanently"):
                    if confirm_text.lower() != "delete my account":
                        st.error("Confirmation text incorrect. Account deletion cancelled.")
                    elif not check_password_hash(user["password_hash"], password):
                        st.error("Invalid password. Account deletion cancelled.")
                    else:
                        # Delete user data
                        delete_user_data(user["user_id"], account["account_no"])
                        logout_user()
                        st.info(f"Account for {user['username']} has been permanently deleted. All data has been removed.")
                        st.rerun()

# Main navigation and app
def main():
    # Initialize everything
    init_files()
    init_session_state()
    load_css()
    
    # Sidebar navigation
    with st.sidebar:
        st.title("🏦 Mini Bank")
        
        if not st.session_state.logged_in:
            st.markdown("### Navigation")
            if st.button("🏠 Home", use_container_width=True, key="sidebar_home"):
                st.session_state.page = 'home'
                st.rerun()
            if st.button("🔑 Login", use_container_width=True, key="sidebar_login"):
                st.session_state.page = 'login'
                st.rerun()
            if st.button("✨ Sign Up", use_container_width=True, key="sidebar_signup"):
                st.session_state.page = 'signup'
                st.rerun()
        else:
            st.markdown(f"### Welcome, {st.session_state.current_user['username']}")
            if st.button("📊 Dashboard", use_container_width=True, key="sidebar_dashboard"):
                st.session_state.page = 'dashboard'
                st.rerun()
            if st.button("🏠 Home", use_container_width=True, key="sidebar_home_logged"):
                st.session_state.page = 'home'
                st.rerun()
            if st.button("🚪 Logout", use_container_width=True, key="sidebar_logout"):
                logout_user()
                st.rerun()
        
        st.markdown("---")
        st.markdown("### 🎓 Developed by")
        st.markdown("**MIT Academy of Engineering**")
        st.markdown("Software Engineering Students")
        
        with st.expander("👥 Development Team"):
            st.markdown("""
            - **Adhav Meghan Nilesh** (PRN: 20230110021)
            - **Sayyed Soha Sameer** (PRN: 20230110023)
            - **Ghadage Mandar Vijaykumar** (PRN: 20230110024)
            - **Jadhav Atharv Shirish** (PRN: 20230110025)
            """)
    
    # Page routing
    try:
        if st.session_state.page == 'home':
            show_home()
        elif st.session_state.page == 'login':
            if st.session_state.logged_in:
                st.session_state.page = 'dashboard'
                st.rerun()
            else:
                show_login()
        elif st.session_state.page == 'signup':
            if st.session_state.logged_in:
                st.session_state.page = 'dashboard'
                st.rerun()
            else:
                show_signup()
        elif st.session_state.page == 'dashboard':
            if not st.session_state.logged_in:
                st.session_state.page = 'login'
                st.rerun()
            else:
                show_dashboard()
        else:
            st.session_state.page = 'home'
            st.rerun()
    except Exception as e:
        st.error(f"An error occurred: {e}")
        st.session_state.page = 'home'
        if st.button("Go to Home", key="error_home"):
            st.rerun()

if __name__ == "__main__":
    main()