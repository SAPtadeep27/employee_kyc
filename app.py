import re 
import tempfile
import base64
from datetime import datetime
from flask import Flask, request, render_template_string, jsonify, render_template, send_from_directory, redirect, session, url_for, flash
from PIL import Image, ImageFilter, ImageOps
import os
from pymongo import MongoClient
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import quote_plus
from google.cloud import vision
from google.oauth2 import service_account
import os, base64
from google.oauth2 import service_account
from google.cloud import vision
from dotenv import load_dotenv
load_dotenv("key.env")

# Read the base64-encoded service account
b64 = os.environ.get("GOOGLE_CREDS_B64")
if not b64:
    raise RuntimeError("Missing GOOGLE_CREDS_B64 env var")

# Write to a temp file in an OS-safe location
with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
    temp_file.write(base64.b64decode(b64))
    creds_path = temp_file.name

# Load the credentials
credentials = service_account.Credentials.from_service_account_file(creds_path)
vision_client = vision.ImageAnnotatorClient(credentials=credentials)
# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
TEMPLATE_HTML = open("templates/index.html").read()

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# MongoDB setup

username = "admin"
raw_password = "jay@1971"

# Encode the password to handle special characters
password = quote_plus(raw_password)

# Create the URI with the encoded password
uri = f"mongodb+srv://{username}:{password}@cluster0.3uxxmqe.mongodb.net/?retryWrites=true&w=majority"

# Connect to MongoDB
client = MongoClient(uri)
db = client["kyc_database"]
collection = db["kyc_forms"]
users_collection = db["users"]

# OCR using Google Cloud Vision
def extract_text_google(img_path):
    with open(img_path, 'rb') as image_file:
        content = image_file.read()
    image = vision.Image(content=content)
    response = vision_client.text_detection(image=image)
    texts = response.text_annotations
    if texts:
        return texts[0].description
    return ""

# Text cleaning
def clean_text(text):
    return "\n".join([line.strip() for line in text.split("\n") if line.strip()])

def parse_aadhaar_front(text):
    data = {}
    text = clean_text(text)
    lines = text.split('\n')

    # Aadhaar number
    aadhaar_match = re.search(r'\b\d{4}\s\d{4}\s\d{4}\b', text)
    if aadhaar_match:
        data['aadhaar_number'] = aadhaar_match.group()

    # DOB
    for line in lines:
        if 'dob' in line.lower():
            dob_match = re.search(r'(\d{2}[\/\-]\d{2}[\/\-]\d{4})', line)
            if dob_match:
                try:
                    dob = datetime.strptime(dob_match.group(1), "%d-%m-%Y")
                except:
                    dob = datetime.strptime(dob_match.group(1), "%d/%m/%Y")
                data['dob'] = dob.strftime('%Y-%m-%d')
                break

    # Issue Date
    for line in lines:
        if 'issue' in line.lower():
            issue_match = re.search(r'(\d{2}[\/\-]\d{2}[\/\-]\d{4})', line)
            if issue_match:
                try:
                    issue_date = datetime.strptime(issue_match.group(1), "%d-%m-%Y")
                except:
                    issue_date = datetime.strptime(issue_match.group(1), "%d/%m/%Y")
                data['issue_date'] = issue_date.strftime('%Y-%m-%d')
                break

    # Gender
    for line in lines:
        if 'male' in line.lower():
            data['gender'] = 'Male'
            break
        elif 'female' in line.lower():
            data['gender'] = 'Female'
            break
        elif 'other' in line.lower():
            data['gender'] = 'Other'
            break

    # Full Name (Line before DOB)
    for i in range(1, len(lines)):
        if 'dob' in lines[i].lower():
            name_line = lines[i - 1].strip()
            clean_name = re.sub(r'[^A-Za-z\s]', '', name_line)
            if 2 <= len(clean_name.split()) <= 4:
                data['full_name'] = clean_name
            break

    return data
def parse_aadhaar_back(text):
    data = {}
    text = clean_text(text)
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    
    address = ""
    capture = False
    for line in lines:
        if "address" in line.lower():
            capture = True
            continue
        if capture:
            if re.search(r'\d{6}', line):  # Likely pin code line
                address += " " + line
                break
            address += " " + line

    if address:
        data['address'] = address.strip()

    return data


import re

def parse_pan(text):
    data = {}
    text = clean_text(text)
    lines = [line.strip() for line in text.split('\n') if line.strip()]

    # Extract PAN number (e.g., BUAPM8868H)
    pan_match = re.search(r'\b[A-Z]{5}\d{4}[A-Z]\b', text)
    if pan_match:
        data['pan_number'] = pan_match.group()

    # Extract father's name (assumed to be the second name line after filtering)
    name_lines = []
    for line in lines:
        if any(word in line.upper() for word in ["INCOME TAX", "GOVT", "PERMANENT", "ACCOUNT", "NUMBER", "SIGNATURE"]):
            continue
        if len(line.split()) >= 2:
            name_lines.append(line)

    if len(name_lines) >= 2:
        data['father_name'] = name_lines[2]

    return data




@app.route('/')
def index():
    if 'user' not in session:
        return redirect('/auth')
    if session.get("role") == "admin":
        return redirect('/admin')
    return redirect('/auth')

@app.route('/form')
def employee_form():
    if 'user' not in session or session.get('role') != 'employee':
        return redirect('/auth')
    return render_template("index.html")

@app.route('/extract', methods=['POST'])
def extract():
    try:
        aadhaar_img = request.files.get('aadhaar_img')
        aadhaar_back_img = request.files.get('aadhaar_back_img')
        pan_img = request.files.get('pan_img')

        if not aadhaar_img or not aadhaar_back_img or not pan_img:
            return jsonify({"error": "All images required."}), 400

        aadhaar_path = os.path.join(app.config['UPLOAD_FOLDER'], aadhaar_img.filename)
        aadhaar_back_path = os.path.join(app.config['UPLOAD_FOLDER'], aadhaar_back_img.filename)
        pan_path = os.path.join(app.config['UPLOAD_FOLDER'], pan_img.filename)

        aadhaar_img.save(aadhaar_path)
        aadhaar_back_img.save(aadhaar_back_path)
        pan_img.save(pan_path)

        aadhaar_text = extract_text_google(aadhaar_path)
        aadhaar_back_text = extract_text_google(aadhaar_back_path)
        pan_text = extract_text_google(pan_path)
        return jsonify({
            "aadhaar_front": parse_aadhaar_front(aadhaar_text),
            "aadhaar_back": parse_aadhaar_back(aadhaar_back_text),
            "pan": parse_pan(pan_text)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/submit', methods=['POST'])
def submit():
    try:
        aadhaar_img = request.files.get('aadhaar_img')
        aadhaar_back_img = request.files.get('aadhaar_back_img')
        pan_img = request.files.get('pan_img')
        user_photo = request.files.get('user_photo')
        cheque_photo = request.files.get('cheque_photo')
        dl_photo = request.files.get('dl_photo')

        if not (aadhaar_img and aadhaar_back_img and pan_img and user_photo and cheque_photo):
            return jsonify({"error": "All mandatory images are required."}), 400

        timestamp = str(datetime.utcnow().timestamp())
        def save_image(img_file, prefix):
            filename = f"{prefix}_{timestamp}_{img_file.filename}"
            img_file.save(os.path.join(UPLOAD_FOLDER, filename))
            return filename

        data = {
            "full_name": request.form.get("full_name"),
            "father_name": request.form.get("father_name"),
            "mother_name": request.form.get("mother_name"),
            "dob": request.form.get("dob"),
            "gender": request.form.get("gender"),
            "marital_status": request.form.get("marital_status"),
            "religion": request.form.get("religion"),
            "nationality": request.form.get("nationality"),
            "address": request.form.get("address"),
            "city": request.form.get("city"),
            "state": request.form.get("state"),
            "pincode": request.form.get("pincode"),
            "phone": request.form.get("phone"),
            "email": request.form.get("email"),
            "aadhaar_number": request.form.get("aadhaar_number"),
            "pan_number": request.form.get("pan_number"),
            "bank_account": request.form.get("bank_account"),
            "ifsc_code": request.form.get("ifsc_code"),
            "upi_id": request.form.get("upi_id"),
            "dl_number": request.form.get("dl_number"),
            "dl_type": request.form.get("dl_type"),
            "dl_issue_date": request.form.get("dl_issue_date"),
            "dl_validity_nt": request.form.get("dl_validity_nt"),
            "emergency_contact": request.form.get("emergency_contact"),
            "remarks": request.form.get("remarks"),
            "aadhaar_img_path": save_image(aadhaar_img, "aadhaar_front"),
            "aadhaar_back_img_path": save_image(aadhaar_back_img, "aadhaar_back"),
            "pan_img_path": save_image(pan_img, "pan"),
            "user_photo_path": save_image(user_photo, "user_photo"),
            "cheque_photo_path": save_image(cheque_photo, "cheque"),
            "dl_photo_path": save_image(dl_photo, "dl_photo") if dl_photo else None,
            "submitted_at": datetime.utcnow()
        }

        collection.insert_one(data)
        return redirect('/thankyou')

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/thankyou')
def thank_you():
    return "<h2>Thank you for your submission. Your form has been submitted successfully.</h2>"

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin')
def admin_dashboard():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect('/auth')
    entries = list(collection.find())
    return render_template('admin.html', entries=entries)

@app.route('/update/<entry_id>', methods=['POST'])
def update_entry(entry_id):
    if 'user' not in session or session.get('role') != 'admin':
        return redirect('/auth')

    updated_data = {key: request.form[key] for key in request.form}
    updated_data = {k: v for k, v in updated_data.items() if v.strip() != ""}

    collection.update_one(
        {"_id": ObjectId(entry_id)},
        {"$set": updated_data}
    )

    return redirect(url_for('admin_dashboard'))


@app.route('/auth', methods=['GET'])
def auth_page():
    return render_template("auth.html")

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get("email")
    password = request.form.get("password")
    confirm = request.form.get("confirm_password")
    role = request.form.get("role") or "employee"

    if not email or not password or not confirm:
        return "All fields are required", 400
    if password != confirm:
        return "Passwords do not match", 400
    if users_collection.find_one({"email": email}):
        return "Email already registered. Please log in.", 400

    users_collection.insert_one({
        "email": email,
        "password": generate_password_hash(password),
        "role": role
    })
    session["user"] = email
    session["role"] = role
    return redirect("/admin" if role == "admin" else "/form")

ADMIN_EMAIL = "jayantamitra07@gmail.com"
ADMIN_HASHED_PASSWORD = "scrypt:32768:8:1$V9EFiD0ccwf4sALK$bff43229810ced319f3147bfdf37ac8a2bdd49fb63a0feedd9e4c5388035c12c4d3f0761d2427c93c09beef0386b450b6c658bbef86318f2ca3e7ee593638b48"

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role') or "employee"

    if role == "admin":
        if email == ADMIN_EMAIL and check_password_hash(ADMIN_HASHED_PASSWORD, password):
            session["user"] = email
            session["role"] = "admin"
            return redirect("/admin")
        return "Invalid admin credentials", 401

    user = users_collection.find_one({"email": email, "role": "employee"})
    if user and check_password_hash(user["password"], password):
        session["user"] = email
        session["role"] = "employee"
        return redirect("/form")

    return "Invalid credentials", 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/auth')

if __name__ == "__main__":
   app.run(host="0.0.0.0", port=5000)
