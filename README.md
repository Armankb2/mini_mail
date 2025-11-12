# 📬 Mini Mail System (Flask + MySQL)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-Framework-orange)](https://flask.palletsprojects.com/)
[![MySQL](https://img.shields.io/badge/Database-MySQL-green)](https://www.mysql.com/)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Windows%20%7C%20Linux-blue)]()

---

## 🧠 Overview  
**Mini Mail** is a lightweight web-based mail system built using **Flask** and **MySQL**.  
It allows users to send and receive internal messages securely, with optional **OTP verification via Twilio**, **file attachments**, and an **Admin Dashboard** to monitor all activities.

---

## ✨ Features

✅ User Registration & Login (PIN-based)  
✅ OTP Verification for Login/Signup *(optional)*  
✅ File Attachments (images, videos, PDFs, docs, etc.)  
✅ Admin Dashboard (View users, messages, logs)  
✅ Message history between users  
✅ Runs locally or via Ngrok for remote access  
✅ Clean UI with custom CSS  

---

## ⚙️ Tech Stack

| Component | Technology |
|------------|-------------|
| **Frontend** | HTML, CSS |
| **Backend** | Flask (Python) |
| **Database** | MySQL |
| **SMS/OTP** | Twilio API |
| **Server Hosting (optional)** | ngrok tunnel |

---

## 🧩 Project Setup Guide

### 1️⃣ Clone this Repository
```bash
git clone https://github.com/<your-username>/mini_mail.git
cd mini_mail

2️⃣ Create a Virtual Environment
python3 -m venv venv
source venv/bin/activate   # For macOS/Linux
venv\Scripts\activate      # For Windows
3️⃣ Install Dependencies
pip install flask mysql-connector-python twilio
4️⃣ Configure MySQL
CREATE DATABASE mail;
CREATE DATABASE feedback;
5️⃣ Update Database & Twilio Credentials
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = "your_mysql_password"

# Optional Twilio OTP config
TWILIO_SID = "your_account_sid"
TWILIO_AUTH = "your_auth_token"
TWILIO_PHONE = "+1xxxxxxxxxx"

6️⃣ Run the Application
python3 mini_mail.py


🧱 Project Structure
mini_mail/
│
├── mini_mail.py           # Main Flask app
├── uploads/               # File uploads
├── logs/                  # Log files (optional)
├── venv/                  # Virtual environment
├── .gitignore
└── README.md              # Project documentation
