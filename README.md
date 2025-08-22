# BytePlus Batch Manager for SSL & WAF

## Overview

The BytePlus Batch Manager for SSL & WAF is a web-based tool designed to simplify and automate the management of SSL certificates and WAF (Web Application Firewall) configurations for domains hosted on the BytePlus platform. It provides a user-friendly interface to perform complex, multi-step operations in batches, significantly reducing manual effort and the potential for errors.

This tool runs locally on your computer, using a lightweight Python backend to securely handle all API communications with BytePlus.

---

## Prerequisites

Before you begin, ensure you have the following installed on your machine (macOS is recommended):

1.  **Homebrew**: The missing package manager for macOS. If you don't have it, you can install it by running the following command in your terminal:
    ```bash
    /bin/bash -c "$(curl -fsSL [https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh](https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh))"
    ```
2.  **Python 3**: The programming language used for the backend server. You can install it easily with Homebrew:
    ```bash
    brew install python
    ```

---

## Setup Instructions

Follow these steps to get the tool running on your local machine.

### Step 1: Download Project Files

Create a new folder on your computer (e.g., `BytePlusTool`) and place the following files inside it:
* `app.html`
* `main.py`
* `ssl_actions.py`
* `waf_actions.py`
* `auth.py`

### Step 2: Create the Configuration File

1.  In the same folder, create a new file named `config.json`.
2.  Copy and paste the following JSON structure into it:

    ```json
    {
      "access_key": "YOUR_ACCESS_KEY_HERE",
      "secret_key": "YOUR_SECRET_KEY_HERE",
      "region": "ap-singapore-1",
      "organization_details": {
        "department": "Your Department",
        "name": "Your Name",
        "postal_code": "",
        "address": "Your Address",
        "city": "Your City",
        "province": "Your Province",
        "country": "SG",
        "email": "your_email@example.com",
        "phone": "Your Phone"
      }
    }
    ```
3.  Replace the placeholder values (`YOUR_..._HERE`) with your actual BytePlus API credentials and organization details.

**⚠️ Important:** Treat the `config.json` file like a password. Do not share it or commit it to public version control systems like GitHub.

### Step 3: Install Python Libraries

1.  Open your terminal or command prompt.
2.  Navigate to your project folder using the `cd` command.
    ```bash
    cd path/to/your/BytePlusTool
    ```
3.  Install the required Python libraries by running the following commands one by one:
    ```bash
    pip3 install flask
    pip3 install requests
    pip3 install flask-cors
    ```

### Step 4: Run the Backend Server

1.  In your terminal (still inside the project folder), run the following command:
    ```bash
    python3 main.py
    ```
2.  If successful, you will see a message like `* Running on http://127.0.0.1:5000`.
3.  **Leave this terminal window open.** It is your running local server.

### Step 5: Launch the Application

1.  Find the `app.html` file in your project folder.
2.  Double-click it to open it in your preferred web browser (e.g., Chrome, Firefox, Safari).

You can now start using the tool!

---

## Step-by-Step Usage Guide

### SSL Management

This tab handles all certificate-related tasks.

#### Creation Workflow

This section is for creating new certificates and performing the initial validation.

1.  **Step 1: Create SSL Orders**
    * Select the desired **Certificate Type** from the dropdown.
    * Enter one or more domains into the **Domains** text area.
    * Click the **Create SSL Orders** button.
    * The **Certificate IDs** box will be auto-populated with the new IDs.

2.  **Step 2: Get DNS Validation Info**
    * With the Certificate IDs from the previous step already in the box, click the **Get DNS Validation Info** button.
    * The **Validation Domain** and **DNS Validation TXT** boxes will be populated.
    * You must now manually add this TXT record to your DNS provider. (If DNS is hosted within same account this will be automated)

3.  **Step 3: Check Cert Status & Binding**
    * After adding the DNS record and waiting a few minutes for it to propagate, click the **Check Cert Status & Binding** button.
    * The **Results** panel will show the current status. Repeat this step until the status shows "Cert Issued".
    * Remark: This usually few mins after the DNS is configure and fully propagate worldwide.

#### Maintenance Workflow

This section is for managing existing certificates, especially for renewals.

1.  **Maint 0: Pull Expiring Certs**
    * Click this button to fetch a list of all certificates that are expiring soon.
    * The results will be formatted and displayed in the **Expiring Certificates** read-only box.

2.  **Maint 1: Replace Cert Orders**
    * From the list of expiring certificates, copy the domains you wish to renew.
    * Paste these domains into the **Domains** text area in the **Creation Workflow** section above.
    * Click the **Replace Cert Orders** button. This will create new certificate orders for the specified domains.

3.  **Maint 3: Bind Certs to Domain**
    * After a replacement certificate has been successfully issued (verified using "Step 3"), paste its new **Certificate ID** into the **Certificate IDs to Bind** box.
    * Paste the corresponding **Domain** into the **Domains to Bind** box.
    * Click the **Bind Certs to Domain** button to deploy the new certificate to the CDN.

#### Hosting & DNS Workflow

This section automates the process of delegating certificate validation to BytePlus.

1.  **Hosting 0: Push DNS API**
    * Click this button to find all certificates in your account that require DNS delegation.
    * The script will automatically create the necessary CNAME records in your BytePlus DNS zone.
    * The **Certs Ready for Hosting** box will be populated with the Certificate IDs that were processed successfully.

2.  **Hosting 1: Check & Host**
    * The Certificate IDs from the previous step will be auto-populated in the main **Certificate IDs** box.
    * Click this button to verify the DNS records and create the final managed hosting task, enabling auto-renewal.

### WAF Management

This tab handles all Web Application Firewall configurations. All actions in this tab apply to the domains listed in the **General** section's "Domains" box.

#### General

* **Add Domain to WAF**: Adds all listed domains to the WAF service.
* **Turn WAF All**: Enables all WAF protection modules for the listed domains.

#### Rate Limiting

* **List RL Rules**: Fetches and displays the rate limiting rules for the *first* domain in the list.
* **Config RL**: Creates new rate limiting rules for *all* listed domains based on the JSON provided in the "Rules" box.
* **Update RL**: Updates existing rules for *all* listed domains. The JSON in the "Rules" box **must** contain an `"Id"`.
* **Delete RL**: Deletes rules for *all* listed domains. You can provide either the full JSON object or just the Rule ID in the "Rules" box.

#### Managed & SEO Bot Rules

The workflow for both sections is the same.

1.  **List Rules**: Enter a single domain in the "General" domains box and click the "List" button to populate the UI with that domain's current configuration.
2.  **Configure**: Make your desired changes in the interactive UI (checking/unchecking boxes, selecting actions).
3.  **Apply**: Add all the domains you want to apply this configuration to in the "General" domains box.
4.  **Click "Config"**: The script will apply the configuration from the UI to every domain listed.

#### Vulnerability

* **List Vul Rules**: Fetches and displays the vulnerability protection settings for the *first* domain in the list, populating the interactive controls.
* **Config Vul Rules**: Applies the settings from the interactive controls (or the custom JSON) to *all* domains listed in the "General" domains box.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
