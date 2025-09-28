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
import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Configuration
DATA_DIR = "data"
QR_DIR = os.path.join("static", "qr")
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
ACCOUNTS_CSV = os.path.join(DATA_DIR, "accounts.csv")
TXNS_CSV = os.path.join(DATA_DIR, "transactions.csv")
PINS_CSV = os.path.join(DATA_DIR, "pins.csv")
BILLS_CSV = os.path.join(DATA_DIR, "bill_payments.csv")

# Page config
st.set_page_config(
    page_title="Mini Bank",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Bill Payment Services Configuration
BILL_SERVICES = {
    "Mobile Recharge": {
        "providers": ["Airtel", "Jio", "Vi (Vodafone Idea)", "BSNL", "Idea", "Vodafone"],
        "icon": "📱",
        "min_amount": 10,
        "max_amount": 5000,
        "field_name": "Mobile Number",
        "field_placeholder": "Enter 10-digit mobile number",
        "field_pattern": r"^\d{10}$"
    },
    "DTH Recharge": {
        "providers": ["Tata Sky", "Dish TV", "Airtel Digital TV", "Sun Direct", "D2H", "DEN"],
        "icon": "📺",
        "min_amount": 50,
        "max_amount": 10000,
        "field_name": "Customer ID",
        "field_placeholder": "Enter 5-digit customer ID",
        "field_pattern": r"^\d{5}$"
    },
    "Electricity Bill": {
        "providers": ["MSEB", "Adani Power", "Tata Power", "BEST", "Reliance Energy", "Other"],
        "icon": "💡",
        "min_amount": 100,
        "max_amount": 50000,
        "field_name": "Consumer Number",
        "field_placeholder": "Enter 12-digit consumer number",
        "field_pattern": r"^\d{12}$"
    },
    "Gas Bill": {
        "providers": ["Indian Oil", "Bharat Petroleum", "Hindustan Petroleum", "Indane Gas", "HP Gas", "Bharatgas"],
        "icon": "🔥",
        "min_amount": 200,
        "max_amount": 20000,
        "field_name": "Consumer Number",
        "field_placeholder": "Enter 10-digit consumer number",
        "field_pattern": r"^\d{10}$"
    },
    "Water Bill": {
        "providers": ["Municipal Corporation", "PCMC", "PMC", "KDMC", "TMC", "Other"],
        "icon": "💧",
        "min_amount": 50,
        "max_amount": 10000,
        "field_name": "Connection ID",
        "field_placeholder": "Enter 8-digit connection ID",
        "field_pattern": r"^\d{8}$"
    },
    "Internet/Broadband": {
        "providers": ["Airtel Fiber", "Jio Fiber", "ACT Fibernet", "BSNL", "Hathway", "Tikona"],
        "icon": "🌐",
        "min_amount": 100,
        "max_amount": 15000,
        "field_name": "Customer ID",
        "field_placeholder": "Enter 5-digit customer ID",
        "field_pattern": r"^\d{5}$"
    },
    "Insurance Premium": {
        "providers": ["LIC", "HDFC Life", "ICICI Prudential", "SBI Life", "Max Life", "Bajaj Allianz"],
        "icon": "🛡️",
        "min_amount": 500,
        "max_amount": 100000,
        "field_name": "Policy Number",
        "field_placeholder": "Enter 9-digit policy number",
        "field_pattern": r"^\d{9}$"
    },
    "Loan EMI": {
        "providers": ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "PNB", "BOI"],
        "icon": "🏠",
        "min_amount": 1000,
        "max_amount": 200000,
        "field_name": "Loan Account Number",
        "field_placeholder": "Enter 12-digit loan account number",
        "field_pattern": r"^\d{12}$"
    },
    "Credit Card Bill": {
        "providers": ["SBI Card", "HDFC Bank", "ICICI Bank", "Axis Bank", "Citibank", "American Express"],
        "icon": "💳",
        "min_amount": 100,
        "max_amount": 500000,
        "field_name": "Credit Card Number",
        "field_placeholder": "Enter last 4 digits of card",
        "field_pattern": r"^\d{4}$"
    },
}

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
    
    if not os.path.exists(BILLS_CSV):
        with open(BILLS_CSV, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["bill_id", "user_id", "account_no", "service_type", "provider", "customer_id", "amount", "date", "status"])

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
        
        .bill-service-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 10px;
            margin-bottom: 1rem;
            text-align: center;
        }
        
        .bill-payment-success {
            background: linear-gradient(135deg, #56ab2f 0%, #a8e6cf 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 10px;
            text-align: center;
            margin: 1rem 0;
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

# Customer ID Generation
def generate_customer_id():
    """Generate a random 5-digit customer ID"""
    import random
    return str(random.randint(10000, 99999))

# Download Functions
def generate_transactions_csv(transactions, username, account_no):
    """Generate CSV data for transactions"""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['Mini Bank - Transaction History'])
    writer.writerow([f'Account Holder: {username}'])
    writer.writerow([f'Account Number: {account_no}'])
    writer.writerow([f'Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'])
    writer.writerow([])  # Empty row
    writer.writerow(['Date', 'Time', 'Type', 'Amount (₹)', 'Description'])
    
    # Transaction data
    for t in transactions:
        try:
            date_str = t['date'].split('T')[0]
            time_str = t['date'].split('T')[1].split('.')[0] if 'T' in t['date'] else t['date']
            
            # Format transaction type
            type_display = {
                'deposit': 'Deposit',
                'withdraw': 'Withdraw', 
                'transfer_in': 'Transfer In',
                'transfer_out': 'Transfer Out',
                'bill_payment': 'Bill Payment'
            }.get(t['type'], t['type'])
            
            writer.writerow([
                date_str,
                time_str,
                type_display,
                f"{float(t['amount']):.2f}",
                t['desc'] or '-'
            ])
        except (ValueError, KeyError):
            continue
    
    return output.getvalue()

def generate_transactions_pdf(transactions, username, account_no):
    """Generate PDF data for transactions"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title = Paragraph("Mini Bank - Transaction History", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 12))
    
    # Account info
    story.append(Paragraph(f"<b>Account Holder:</b> {username}", styles['Normal']))
    story.append(Paragraph(f"<b>Account Number:</b> {account_no}", styles['Normal']))
    story.append(Paragraph(f"<b>Generated on:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Table data
    table_data = [['Date', 'Time', 'Type', 'Amount (₹)', 'Description']]
    
    for t in transactions:
        try:
            date_str = t['date'].split('T')[0]
            time_str = t['date'].split('T')[1].split('.')[0] if 'T' in t['date'] else t['date']
            
            # Format transaction type
            type_display = {
                'deposit': 'Deposit',
                'withdraw': 'Withdraw', 
                'transfer_in': 'Transfer In',
                'transfer_out': 'Transfer Out',
                'bill_payment': 'Bill Payment'
            }.get(t['type'], t['type'])
            
            table_data.append([
                date_str,
                time_str,
                type_display,
                f"{float(t['amount']):.2f}",
                t['desc'] or '-'
            ])
        except (ValueError, KeyError):
            continue
    
    # Create table
    table = Table(table_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(table)
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

# Bill Payment Functions
def add_bill_payment(user_id, account_no, service_type, provider, customer_id, amount):
    bill_id = str(uuid.uuid4())
    append_csv(BILLS_CSV, ["bill_id", "user_id", "account_no", "service_type", "provider", "customer_id", "amount", "date", "status"], {
        "bill_id": bill_id,
        "user_id": user_id,
        "account_no": account_no,
        "service_type": service_type,
        "provider": provider,
        "customer_id": customer_id,
        "amount": f"{float(amount):.2f}",
        "date": datetime.datetime.utcnow().isoformat(),
        "status": "Completed"
    })
    return bill_id

def get_bill_payments_for_user(user_id, limit=50):
    rows = [b for b in read_csv(BILLS_CSV) if b["user_id"] == user_id]
    rows.sort(key=lambda r: r["date"], reverse=True)
    return rows[:limit]

def process_bill_payment(user_id, account_no, service_type, provider, customer_id, amount, pin):
    # Verify PIN
    if not verify_user_pin(user_id, pin):
        return False, "Invalid PIN. Payment cancelled for security."
    
    # Get account details
    account = get_account_by_accountno(account_no)
    if not account:
        return False, "Account not found."
    
    # Check balance
    if float(account["balance"]) < amount:
        return False, "Insufficient funds."
    
    # Process payment
    try:
        # Deduct amount from account
        new_balance = float(account["balance"]) - amount
        update_account_balance(account_no, new_balance)
        
        # Add transaction record
        desc = f"{service_type} - {provider} ({customer_id})"
        add_transaction(account_no, "bill_payment", amount, desc)
        
        # Add bill payment record
        bill_id = add_bill_payment(user_id, account_no, service_type, provider, customer_id, amount)
        
        return True, f"Payment successful! Bill ID: {bill_id[:8]}"
    except Exception as e:
        return False, f"Payment failed: {str(e)}"

# Password validation
def is_password_strong(pw: str) -> bool:
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$'
    return bool(re.match(pattern, pw))

def is_pin_valid(pin: str) -> bool:
    return bool(re.match(r'^\d{4}$', pin))

def validate_service_field(service_type, value):
    if service_type not in BILL_SERVICES:
        return False
    pattern = BILL_SERVICES[service_type]["field_pattern"]
    return bool(re.match(pattern, value))

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
        
        # Delete from bill_payments.csv
        bills = read_csv(BILLS_CSV)
        bills = [b for b in bills if b["user_id"] != user_id]
        write_csv_atomic(BILLS_CSV, ["bill_id", "user_id", "account_no", "service_type", "provider", "customer_id", "amount", "date", "status"], bills)
        
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
                <h4>🔒 Bank-Grade Security</h4>
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
                <h4>🧾 Bill Payment System</h4>
                <p>Pay utilities, mobile recharge, DTH, insurance, and more with secure PIN protection.</p>
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
        password = st.text_input("🔒 Password", type="password")
        
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
        password = st.text_input("🔒 Create Password", type="password")
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

def show_bill_payment():
    user = st.session_state.current_user
    account = get_account_by_user(user["user_id"])
    has_pin = user_has_pin(user["user_id"])
    
    st.markdown("""
    <div class="main-header">
        <h1>🧾 Bill Payment Center</h1>
        <p>Pay your bills securely and conveniently</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Auto-generated Customer IDs display
    st.markdown("### 🆔 Your Auto-Generated Customer IDs")
    
    # Generate customer IDs for services that require 5-digit IDs
    dth_id = generate_customer_id()
    internet_id = generate_customer_id()
    
    st.markdown(f"""
    <div class="feature-box">
        <p><strong>📺 DTH Recharge:</strong> <code>{dth_id}</code></p>
        <p><strong>🌐 Internet/Broadband:</strong> <code>{internet_id}</code></p>
        <p><em>Use these customer IDs when making payments for the respective services.</em></p>
    </div>
    """, unsafe_allow_html=True)
    
    if not has_pin:
        st.markdown("""
        <div class="pin-required-banner">
            <h3>🔒 PIN Setup Required</h3>
            <p>To make secure bill payments, please set up your 4-digit PIN first.</p>
            <p><strong>🚫 All bill payment features are disabled until PIN is set</strong></p>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🔒 Set PIN Now", use_container_width=True):
            st.session_state.page = 'dashboard'
            st.session_state.show_pin_modal = True
            st.rerun()
        return
    
    # Current balance display
    st.markdown(f"""
    <div class="balance-card">
        <h3>💳 Available Balance</h3>
        <h2>💰 ₹ {float(account['balance']):.2f}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Service Selection
    st.subheader("🏪 Select Service")
    
    # Display available services in a grid
    cols = st.columns(3)
    for idx, (service, details) in enumerate(BILL_SERVICES.items()):
        with cols[idx % 3]:
            st.markdown(f"""
            <div class="bill-service-card">
                <h4>{details['icon']} {service}</h4>
                <p>₹{details['min_amount']} - ₹{details['max_amount']}</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Service selection dropdown
    selected_service = st.selectbox(
        "Choose a service:",
        options=list(BILL_SERVICES.keys()),
        index=0
    )
    
    if selected_service:
        service_details = BILL_SERVICES[selected_service]
        
        st.markdown("---")
        st.subheader(f"{service_details['icon']} {selected_service} Payment")
        
        with st.form("bill_payment_form"):
            # Provider selection
            provider = st.selectbox(
                "Select Provider:",
                options=service_details["providers"]
            )
            
            # Customer ID/Number input
            customer_id = st.text_input(
                f"{service_details['field_name']}:",
                placeholder=service_details['field_placeholder'],
                help=f"Enter your {service_details['field_name'].lower()}"
            )
            
            # Amount input
            amount = st.number_input(
                "Payment Amount (₹):",
                min_value=float(service_details['min_amount']),
                max_value=float(service_details['max_amount']),
                step=0.01,
                help=f"Amount range: ₹{service_details['min_amount']} - ₹{service_details['max_amount']}"
            )
            
            # PIN input
            pin = st.text_input(
                "🔒 Enter 4-digit PIN:",
                type="password",
                max_chars=4,
                help="Enter your secure 4-digit PIN to authorize payment"
            )
            
            # Payment button
            submitted = st.form_submit_button(
                f"💳 Pay ₹{amount:.2f}",
                use_container_width=True
            )
            
            if submitted:
                # Validation
                if not customer_id:
                    st.error(f"Please enter {service_details['field_name'].lower()}")
                elif not validate_service_field(selected_service, customer_id):
                    st.error(f"Invalid {service_details['field_name'].lower()} format")
                elif not is_pin_valid(pin):
                    st.error("PIN must be exactly 4 digits")
                elif amount < service_details['min_amount'] or amount > service_details['max_amount']:
                    st.error(f"Amount must be between ₹{service_details['min_amount']} and ₹{service_details['max_amount']}")
                else:
                    # Process payment
                    success, message = process_bill_payment(
                        user["user_id"], 
                        account["account_no"], 
                        selected_service, 
                        provider, 
                        customer_id, 
                        amount, 
                        pin
                    )
                    
                    if success:
                        st.markdown(f"""
                        <div class="bill-payment-success">
                            <h3>✅ Payment Successful!</h3>
                            <p><strong>{message}</strong></p>
                            <p>Service: {selected_service}</p>
                            <p>Provider: {provider}</p>
                            <p>Customer ID: {customer_id}</p>
                            <p>Amount Paid: ₹{amount:.2f}</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Auto-refresh to show updated balance
                        st.rerun()
                    else:
                        st.error(f"Payment Failed: {message}")
    
    st.markdown("---")
    
    # Recent Bill Payments
    st.subheader("📋 Recent Bill Payments")
    
    bill_payments = get_bill_payments_for_user(user["user_id"])
    
    if bill_payments:
        # Convert to DataFrame for better display
        df_data = []
        for bill in bill_payments:
            try:
                date_str = bill['date'].split('T')[0]
                time_str = bill['date'].split('T')[1].split('.')[0] if 'T' in bill['date'] else bill['date']
                
                df_data.append({
                    'Date': date_str,
                    'Time': time_str,
                    'Service': bill['service_type'],
                    'Provider': bill['provider'],
                    'Customer ID': bill['customer_id'],
                    'Amount': f"₹ {float(bill['amount']):.2f}",
                    'Status': bill['status'],
                    'Bill ID': bill['bill_id'][:8] + "..."
                })
            except (ValueError, KeyError):
                continue
        
        if df_data:
            df = pd.DataFrame(df_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No valid bill payment records found.")
    else:
        st.info("No bill payments made yet. Start by paying your first bill!")
    
    # Navigation buttons
    st.markdown("---")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🏠 Back to Dashboard", use_container_width=True):
            st.session_state.page = 'dashboard'
            st.rerun()
    
    with col2:
        if st.button("🔄 Refresh", use_container_width=True):
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
            <h3>🔒 Security Setup Required</h3>
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
        
        # Quick Actions
        st.subheader("⚡ Quick Actions")
        
        action_col1, action_col2 = st.columns(2)
        
        with action_col1:
            if st.button("🧾 Pay Bills", use_container_width=True, key="pay_bills_btn"):
                st.session_state.page = 'bill_payment'
                st.rerun()
        
        
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
                <h4>🔐 Security Notice</h4>
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
        st.subheader("🔒 PIN Security")
        
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
        if st.button("🔒 Set PIN" if not has_pin else "🔄 Change PIN", use_container_width=True, key="set_pin_btn"):
            st.session_state.show_pin_modal = True
        
        # PIN Setup Modal
        if st.session_state.show_pin_modal:
            st.markdown("---")
            st.subheader("🔒 Set PIN" if not has_pin else "🔄 Change PIN")
            
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
                            st.success("PIN set successfully! You can now make secure deposits, withdrawals, transfers, and bill payments.")
                        st.rerun()
    
    st.markdown("---")
    
    # Transaction History
    st.subheader("📊 Recent Transactions")
    txns = get_transactions_for_account(account["account_no"])
    
    if txns:
        # Download buttons
        col1, col2, col3 = st.columns([1, 1, 4])
        
        with col1:
            if st.button("📄 Download CSV", use_container_width=True, key="download_csv"):
                csv_data = generate_transactions_csv(txns, user['username'], account['account_no'])
                st.download_button(
                    label="💾 Download CSV File",
                    data=csv_data,
                    file_name=f"transactions_{account['account_no']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    key="csv_download"
                )
        
        with col2:
            if st.button("📋 Download PDF", use_container_width=True, key="download_pdf"):
                pdf_data = generate_transactions_pdf(txns, user['username'], account['account_no'])
                st.download_button(
                    label="📄 Download PDF File",
                    data=pdf_data,
                    file_name=f"transactions_{account['account_no']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    key="pdf_download"
                )
        
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
                    'transfer_out': '📤 Transfer Out',
                    'bill_payment': '🧾 Bill Payment'
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
        st.info("No transactions yet. " + ("Start by making a deposit, transfer, or bill payment!" if has_pin else "Set your PIN first, then start making transactions!"))
    
    st.markdown("---")
    
    # Account Management
    st.subheader("⚙️ Account Management")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("🏠 Home", use_container_width=True, key="dash_home"):
            st.session_state.page = 'home'
            st.rerun()
    
    with col2:
        if st.button("🧾 Bill Payments", use_container_width=True, key="dash_bills"):
            st.session_state.page = 'bill_payment'
            st.rerun()
    
    with col3:
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
            if st.button("🧾 Bill Payments", use_container_width=True, key="sidebar_bills"):
                st.session_state.page = 'bill_payment'
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
        elif st.session_state.page == 'bill_payment':
            if not st.session_state.logged_in:
                st.session_state.page = 'login'
                st.rerun()
            else:
                show_bill_payment()
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
