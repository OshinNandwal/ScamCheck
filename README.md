🛡️ ScamCheck

ScamCheck is a Python and Streamlit-based application that analyzes suspicious messages, emails, phone numbers, and URLs to identify potential scam patterns and estimate their risk level.

The application uses rule-based text analysis, pattern detection, category scoring, and risk indicators to provide an understandable scam assessment.

✨ Features

•🔎 Analyze suspicious messages and text

•📧 Detect suspicious email patterns

•📱 Identify potentially suspicious Indian phone numbers

•🔗 Detect suspicious URLs and links

•🏦 Identify banking and OTP-related scam indicators

•💼 Detect job and work-from-home scam patterns

•📦 Detect delivery and parcel scam patterns

•💰 Identify investment and payment-related scam patterns

•🎁 Detect lottery and reward scam patterns

•🖥️ Detect technical-support scam patterns

•👤 Identify impersonation and social-engineering indicators

•📊 Generate an overall risk score

•📈 Provide category-based risk analysis

•🧾 Display evidence and detected indicators

•📄 Generate downloadable PDF reports

•🕘 Maintain a local scan history

•🇮🇳 Includes detection patterns relevant to scams targeting users in India



🔍 Scam Categories

ScamCheck can classify suspicious content into categories such as:

•Banking Scam

•OTP Scam

•Phishing

•Job Scam

•Investment Scam

•Delivery Scam

•Lottery / Reward Scam

•Tech Support Scam

•Impersonation

•Romance / Social Engineering

•Suspicious URL

•Suspicious Phone Number

•Suspicious Email



🧠 How It Works

ScamCheck analyzes the supplied content using multiple signals, including:

1.Urgency and pressure tactics

2.Requests for money or payments

3.Requests for OTPs or sensitive information

4.Suspicious links and URLs

5.Job-related payment requests

6.Investment-related promises

7.Banking terminology

8.Delivery and parcel-related patterns

9.Impersonation indicators

10.Threats, secrecy, and social-engineering patterns

The detected signals contribute to category scores and an overall risk assessment.



📊 Risk Assessment

The application provides:

•Overall risk score

•Risk level

•Confidence estimate

•Classification

•Detected evidence

•Category-level scoring

•Explanation of suspicious indicators

The result is intended as an assistive scam-screening tool, not as a definitive determination that a message is fraudulent.



🛠️ Technologies Used

Programming

•Python

Framework

•Streamlit

Libraries

•Pandas

•NumPy

•Scikit-learn

•ReportLab

Other Tools

•Git

•GitHub

•Jupyter

•VS Code



📁 Project Structure

ScamCheck/

├── app.py

├── requirements.txt

├── README.md

├── .gitignore

└── scan\_history.json

scan\_history.json is excluded from Git tracking because it contains locally generated scan history.



🚀 Installation

Clone the repository:

git clone https://github.com/YOUR-GITHUB-USERNAME/ScamCheck.git

Move into the project directory:

cd ScamCheck

Install the required dependencies:

pip install -r requirements.txt

Run the application:

streamlit run app.py

The application will open in your browser at the local Streamlit address.



🧪 Example

Example suspicious message:

Congratulations! You have been selected for a work-from-home

job. Pay a small registration fee immediately to confirm your

position. Click the link below to complete your verification.

ScamCheck can identify signals such as:

•Job opportunity

•Upfront payment request

•Urgency

•Link interaction

•Suspicious employment pattern



🔐 Privacy

ScamCheck is designed as a local Streamlit application. Scan history is stored locally and is excluded from the Git repository through .gitignore.

Users should avoid entering real passwords, OTPs, financial credentials, or other sensitive personal information while testing the application.

🎯 Project Purpose

ScamCheck was developed as a practical cybersecurity and data-analysis project to explore how suspicious communication patterns can be identified using automated rule-based analysis and risk scoring.

👩‍💻 Author

Oshin Nandwal

B.Tech Computer Science Engineering — Data Science

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

⭐ If you find the project useful, consider giving the repository a star.





