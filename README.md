# **Push, Deploy, Repeat: Automating Server Updates with GitHub Webhooks 🚀**  

This repository accompanies the article _["Push, Deploy, Repeat: Automating Server Updates with GitHub Webhooks"](https://lambdasandlapdogs.com/)_. It demonstrates how to automatically update a server every time a new commit is pushed to the `main` branch of a GitHub repository, using Flask and webhooks.

## **Table of Contents**  
- [**Push, Deploy, Repeat: Automating Server Updates with GitHub Webhooks 🚀**](#push-deploy-repeat-automating-server-updates-with-github-webhooks-)
  - [**Table of Contents**](#table-of-contents)
  - [**Overview**](#overview)
  - [**Features**](#features)
  - [**Setup Instructions**](#setup-instructions)
    - [1. **Clone the Repository**](#1-clone-the-repository)
    - [2. **Set Up a Virtual Environment**](#2-set-up-a-virtual-environment)
    - [3. **Install Dependencies**](#3-install-dependencies)
    - [4. **Configure the Secret Key**](#4-configure-the-secret-key)
  - [**How It Works**](#how-it-works)
  - [**Testing the Webhook**](#testing-the-webhook)
  - [**Security Considerations**](#security-considerations)
  - [**License**](#license)

---

## **Overview**  
This project automates the deployment process by using a webhook listener to pull the latest code from the GitHub repository when a push event is detected on the `main` branch.

---

## **Features**  
- **Automatic Pull from Main Branch:** Ensures the server always runs the latest code.  
- **Secure Webhook Integration:** Validates requests using a GitHub IP whitelist and HMAC signature verification.  
- **Modular Design:** Blueprint-based structure for easy extensibility.  
- **Error Handling:** Handles network issues, invalid IPs, and signature mismatches gracefully.

---

## **Setup Instructions**  

### 1. **Clone the Repository**  
```bash
git clone https://github.com/tyler-tee/push-deploy-repeat.git
cd push-deploy-repeat
```

### 2. **Set Up a Virtual Environment**  
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
venv\Scripts\activate  # On Windows
```

### 3. **Install Dependencies**  
```bash
pip install -r requirements.txt
```

### 4. **Configure the Secret Key**  
1. Open the existing config/update_config.json file.
2. Replace the placeholder secret token with your desired secret token:

```json
{
    "SECRET_KEY": "your-secret-token"
}
```

3. Use the same **secret token** in your GitHub webhook configuration.

---

## **How It Works**  
1. **GitHub Webhook Setup:**  
   - GitHub sends a POST request to the server’s `/update_server` endpoint on every push to the `main` branch.

2. **IP Validation:**  
   - The server verifies that the request originated from GitHub by checking the IP range.

3. **Signature Verification:**  
   - The payload’s HMAC signature is compared with the secret key to prevent unauthorized access.

4. **Code Pull and Update:**  
   - If the validation passes, the server pulls the latest code from the `main` branch using Git.

---

## **Testing the Webhook**  
1. **Start the Flask App:**  
   ```bash
   python app.py
   ```

2. **Configure the GitHub Webhook:**  
   - In your GitHub repository, go to **Settings** → **Webhooks**.  
   - Add a new webhook with the following details:
     - **Payload URL:** `http://<your-server-ip>:5000/webhook/update_server`
     - **Content type:** `application/json`
     - **Secret:** Use the same secret from `update_config.json`
     - **Events:** Select **Just the push event**.

3. **Push a Commit:**  
   - Push a new commit to the `main` branch:
     ```bash
     git add .
     git commit -m "Test webhook"
     git push origin main
     ```

4. **Check the Server Logs:**  
   - Ensure the server receives the event and pulls the latest code successfully.

---

## **Security Considerations**  
- **IP Whitelisting:** Verifies that the request originates from GitHub’s IP range using the [GitHub Meta API](https://api.github.com/meta).  
- **Signature Validation:** Uses HMAC with SHA-256 to validate the payload against the configured secret.  
- **HTTPS:** Ensure your server is secured with SSL/TLS for production use.  

---

## **License**  
This project is licensed under the MIT License.

---
