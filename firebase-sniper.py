import subprocess
import re
import requests
import sys
import json
import os
import random
import argparse

"""
Firebase Sniper - Test Firebase security misconfigurations in APKs
This tool is based on the amazing work of Suryesh
https://github.com/Suryesh/Firebase-Checker
"""

OUTPUT_FILE='firebase_sniper_results.txt'
USER_AGENT='BUGBOUNTY'

def print_to_output(string):
    """Prints a string to the output file."""
    with open(OUTPUT_FILE, 'a') as f:
        f.write(string + '\n')

# Extract info from apk file
def extract_info_from_apk(apk_path):
    """Extracts App ID, Firebase URL, and Google API Key from an APK file."""
    result = subprocess.run(['strings', apk_path], capture_output=True, text=True)
    strings_output = result.stdout

    app_id_match = re.search(r'1:(\d+):android:([a-f0-9]+)', strings_output)
    firebase_url_match = re.search(r'https://[a-zA-Z0-9-]+\.firebaseio\.com', strings_output)
    google_api_key_match = re.search(r'AIza[0-9A-Za-z-_]{35}', strings_output)
    storage_bucket_match = re.search(r'([a-zA-Z0-9-]+)\.appspot\.com', strings_output)

    app_id = app_id_match.group(0) if app_id_match else None
    firebase_url = firebase_url_match.group(0) if firebase_url_match else None
    google_api_key = google_api_key_match.group(0) if google_api_key_match else None
    storage_bucket = storage_bucket_match.group(0) if storage_bucket_match else None

    return app_id, firebase_url, google_api_key, storage_bucket

def send_alert(message):
    print_to_output(f"ALERT : {message}")

def execute_curl_command(curl_cmd):
    """Executes a curl command and prints the output."""
    curl_cmd = curl_cmd + f" -H 'User-Agent: {USER_AGENT}'"
    print_to_output(f"\nExecuting Curl Command: {curl_cmd}")
    result = subprocess.run(curl_cmd , shell=True, capture_output=True, text=True)
    print_to_output(f"\nCurl Output:\n{result.stdout}")
    return result.stdout

# Checkings files type in bucket
def get_file_type(filename):
    """Dynamically detect file type from extension or content."""
    media_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', 
                       '.mp4', '.avi', '.mov', '.mkv', '.webm',
                       '.mp3', '.wav', '.ogg', '.m4a',
                       '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar']
    
    data_extensions = ['.json', '.xml', '.txt', '.csv', '.log']
    file_ext = os.path.splitext(filename.lower())[1]
    
    if file_ext in media_extensions:
        return 'media'
    elif file_ext in data_extensions:
        return 'data'
    elif any(keyword in filename.lower() for keyword in ['config', 'settings', 'data', 'user', 'profile']):
        return 'data'
    else:
        return 'unknown'

# testing file is accessible or not
def test_file_access(bucket_name, file_path, file_type):
    """Test file access based on file type."""
    try:
        encoded_path = quote(file_path, safe='')
        test_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket_name}/o/{encoded_path}"
        
        response = requests.get(test_url, timeout=10)
        if response.status_code == 200:
            file_info = response.json()
            download_tokens = file_info.get('downloadTokens')
            
            if download_tokens:
                download_url = f"{test_url}?alt=media&token={download_tokens}"
                
                if file_type == 'media':
                    # For media files, test download
                    download_response = requests.get(download_url, timeout=10)
                    if download_response.status_code == 200:
                        return "Media file downloadable"
                    else:
                        return f"Media download failed: {download_response.status_code}"
                else:
                    # For data files, fetch and display content
                    download_response = requests.get(download_url, timeout=10)
                    if download_response.status_code == 200:
                        content = download_response.text
                        if len(content) > 500:  # Truncate long content
                            content = content[:500] + "..."
                        return f"Data file accessible. Content preview: {content}"
                    else:
                        return f"Data access failed: {download_response.status_code}"
            else:
                return "No download token"
        else:
            return f"Access denied: {response.status_code}"
    except Exception as e:
        return f"File test failed: {str(e)}"

# Firebase Storage vulnerability check
def check_firebase_storage(storage_bucket):
    """Checks for Firebase Storage vulnerabilities."""
    vulnerabilities = []
    downloadable_files = []
    
    if not storage_bucket:
        vulnerabilities.append(("Storage bucket not provided", "info"))
        return vulnerabilities, downloadable_files
    
    try:
        storage_url = f"https://firebasestorage.googleapis.com/v0/b/{storage_bucket}/o/"
        print_to_output(f"\n🔍 Testing Firebase Storage Bucket: {storage_bucket}")
        
        response = requests.get(storage_url, timeout=10)
        
        if response.status_code == 200:
            vulnerabilities.append(("Firebase storage publicly readable - file exposure detected", "vulnerable"))
            send_alert(f"Open Firebase storage detected. Bucket: {storage_bucket}")
            execute_curl_command(f'curl "{storage_url}"')
            
            try:
                data = response.json()
                if 'items' in data:
                    file_count = len(data['items'])
                    vulnerabilities.append((f"Found {file_count} files in storage", "vulnerable"))
                    
                    for item in data['items']:
                        name = item.get('name', 'Unknown')
                        size = item.get('size', 0)
                        file_type = get_file_type(name)
                        
                        access_test = test_file_access(storage_bucket, name, file_type)
                        if "downloadable" in access_test.lower() or "accessible" in access_test.lower():
                            downloadable_files.append((file_type, name, size))
                    
                    if downloadable_files:
                        vulnerabilities.append((f"Accessible files found: {len(downloadable_files)}/{file_count}", "vulnerable"))
                        
                        display_count = min(5, len(downloadable_files))
                        vulnerabilities.append((f"First {display_count} accessible files:", "info"))
                        for i, (file_type, file_path, size) in enumerate(downloadable_files[:display_count]):
                            vulnerabilities.append((f"  {i+1}. {file_path} ({size} bytes) [{file_type}]", "info"))
                        
                        if len(downloadable_files) > display_count:
                            vulnerabilities.append((f"  ... and {len(downloadable_files) - display_count} more files", "info"))
                    else:
                        vulnerabilities.append(("No accessible files found", "secure"))
                            
                else:
                    vulnerabilities.append(("No files found in storage bucket", "secure"))
                    
            except Exception as e:
                vulnerabilities.append((f"Error parsing storage response: {e}", "error"))
                
        elif response.status_code == 400:
            vulnerabilities.append(("Firebase Storage bucket listing disabled - secure", "secure"))
            execute_curl_command(f'curl "{storage_url}"')
        elif response.status_code == 401:
            vulnerabilities.append(("Firebase Storage requires authentication - secure", "secure"))
            execute_curl_command(f'curl "{storage_url}"')
        elif response.status_code == 403:
            vulnerabilities.append(("Firebase Storage access forbidden - secure", "secure"))
            execute_curl_command(f'curl "{storage_url}"')
        elif response.status_code == 404:
            vulnerabilities.append(("Firebase Storage bucket not found", "info"))
            execute_curl_command(f'curl "{storage_url}"')
        else:
            vulnerabilities.append((f"Storage bucket returned HTTP {response.status_code}", "info"))
            execute_curl_command(f'curl "{storage_url}"')
    
    except Exception as e:
        vulnerabilities.append((f"Storage test failed: {str(e)}", "error"))
        try:
            storage_url = f"https://firebasestorage.googleapis.com/v0/b/{storage_bucket}/o/"
            execute_curl_command(f'curl "{storage_url}"')
        except:
            pass
    
    return vulnerabilities, downloadable_files


def offer_file_downloads(storage_bucket, downloadable_files):
    """
    Print accessible files summary.
    - If fewer than 10 files: print full list
    - If 10 or more files: print only the count
    """

    if not downloadable_files:
        return

    total = len(downloadable_files)

    if total < 10:
        print_to_output(f"\n📥 Downloadable Files Found ({total} files)")
        for i, (file_type, file_path, size) in enumerate(downloadable_files, 1):
            print_to_output(f"{i}. {file_path} ({size} bytes) [{file_type}]")
    else:
        print_to_output(f"\n📥 {total} downloadable files are accessible")


# Checking for open database
def check_firebase_vulnerability(firebase_url, google_api_key, app_id):
    """Checks for Firebase vulnerabilities, including open databases and unauthorized signup."""
    vulnerabilities = []
    print_to_output(f"\n🔍 Testing Firebase Database...")
    

    if firebase_url:
        try:
            print_to_output(f"Testing database URL: {firebase_url}")
            response = requests.get(f"{firebase_url}/.json", timeout=10)
            execute_curl_command(f"curl \"{firebase_url}/.json\"")
            
            if response.status_code == 200:
                vulnerabilities.append(("Firebase database (.json) publicly readable - data exposure detected", "vulnerable"))
                print_to_output("✅ Database is publicly accessible!")
                send_alert(f"Open Firebase database detected. URL: {firebase_url}")

                try:
                    data = response.json()
                    if data:
                        data_str = str(data)
                        if len(data_str) > 200:
                            data_str = data_str[:200] + "..."
                        print_to_output(f"📊 Sample data: {data_str}")
                except:
                    print_to_output("📊 Database accessible but data format not readable")
                    
            elif response.status_code == 401:
                vulnerabilities.append(("Firebase database requires authentication - secure", "secure"))
                print_to_output("🔒 Database requires authentication - Secure")
            elif response.status_code == 403:
                vulnerabilities.append(("Firebase database access forbidden - secure", "secure"))
                print_to_output("🔒 Database access forbidden - Secure")
            elif response.status_code == 404:
                vulnerabilities.append(("Firebase database not found", "info"))
                print_to_output("❓ Firebase database not found")
            else:
                vulnerabilities.append(("Firebase database (.json) is not openly accessible", "secure"))
                print_to_output("🔒 Database not publicly accessible - Secure")
                
        except requests.RequestException as e:
            vulnerabilities.append((f"Failed to check Firebase database: {str(e)}", "error"))
            print_to_output(f"❌ Database test failed: {str(e)}")
            # ERROR MEIN BHI CURL TRY KARO
            try:
                execute_curl_command(f"curl \"{firebase_url}/.json\"")
            except:
                pass
    else:
        vulnerabilities.append(("Firebase URL not provided - skipping database test", "info"))
        print_to_output("ℹ️  No Firebase URL provided for database test")

    # checking for remoteconfig file
    print_to_output(f"\n🔍 Testing Firebase Remote Config...")
    

    if google_api_key and app_id:
        try:
            project_id = None
            
            if ':' in app_id and 'android' in app_id:
                project_id = app_id.split(':')[1]
            elif ':' in app_id and 'web' in app_id:
                project_id = app_id.split(':')[1]
            elif ':' in app_id and 'ios' in app_id:
                project_id = app_id.split(':')[1]
            elif app_id.isdigit():
                project_id = app_id
            else:
                numbers = re.findall(r'\d+', app_id)
                if numbers:
                    project_id = numbers[0]
            
            if project_id:
                url = f"https://firebaseremoteconfig.googleapis.com/v1/projects/{project_id}/namespaces/firebase:fetch?key={google_api_key}"
                body = {"appId": app_id, "appInstanceId": "required_but_unused_value"}

                response = requests.post(url, json=body, timeout=5)
                if response.status_code == 200 and response.json().get("state") != "NO_TEMPLATE":
                    vulnerabilities.append(("Firebase Remote Config is enabled", "vulnerable"))
                    send_alert(f"Firebase Remote Config enabled. URL: {url}")
                    
                    print_to_output("✅ Remote Config is accessible!")
                    execute_curl_command(f"curl -X POST '{url}' -H 'Content-Type: application/json' -d '{json.dumps(body)}'")
                else:
                    vulnerabilities.append(("Firebase Remote Config is disabled or inaccessible", "secure"))
                    print_to_output("🔒 Remote Config not accessible - Secure")
            else:
                vulnerabilities.append(("Could not extract project ID for Remote Config test", "info"))
                print_to_output("ℹ️  Could not extract project ID")
                
        except requests.RequestException as e:
            vulnerabilities.append((f"Failed to check Firebase Remote Config: {str(e)}", "error"))
            print_to_output(f"❌ Remote Config test failed: {str(e)}")
    else:
        vulnerabilities.append(("Google API Key or App ID missing - skipping Remote Config test", "info"))
        print_to_output("ℹ️  Missing API Key or App ID for Remote Config test")

    return vulnerabilities

def send_verification_email(api_key, id_token):
    """Send email verification link using idToken"""
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={api_key}"
    payload = {
        "requestType": "VERIFY_EMAIL",
        "idToken": id_token
    }

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print_to_output("\n[+] Verification email sent successfully!")
            print_to_output("Check the inbox of the registered email")
            return True
        else:
            print_to_output(f"\n[!] Failed to send verification (HTTP {response.status_code})")
            return False
    except Exception as e:
        print_to_output(f"\n[!] Error: {str(e)}")
        return False

# checking for anonymous signup
def check_unauthorized_signup(google_api_key, user_email):
    """Checks if unauthorized Firebase signup is possible."""
    vulnerabilities = []
    id_token = None

    if not google_api_key:
        vulnerabilities.append(("Google API Key not provided - cannot test signup", "info"))
        return vulnerabilities

    signup_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={google_api_key}"
    signup_payload = json.dumps({"email": user_email, "password": "Test@Pass123", "returnSecureToken": True})


    print_to_output(f"\n🔍 Testing unauthorized signup on {signup_url}")
    response = execute_curl_command(f"curl -X POST '{signup_url}' -H 'Content-Type: application/json' -d '{signup_payload}'")

    if 'idToken' in response:
        vulnerabilities.append(("Unauthorized Firebase signup is enabled - security risk", "vulnerable"))
        send_alert("✅ Unauthorized signup is enabled!...")
        
        try:
            response_json = json.loads(response)
            id_token = response_json.get("idToken")
            refresh_token = response_json.get("refreshToken")

            if id_token:
                print_to_output("\nAttempting to send verification email...")
                send_verification_email(google_api_key, id_token)
               
            if refresh_token:
                token_url = f"https://securetoken.googleapis.com/v1/token?key={google_api_key}"
                token_payload = json.dumps({"grant_type": "refresh_token", "refresh_token": refresh_token})
                send_alert("Fetching access token using refresh token...")
                execute_curl_command(f"curl -X POST '{token_url}' -H 'Content-Type: application/json' -d '{token_payload}'")
        except:
            vulnerabilities.append(("Error processing signup response", "error"))

    if id_token:
        lookup_url = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={google_api_key}"
        lookup_payload = json.dumps({"idToken": id_token})
        send_alert("Fetching account information using idToken...")
        execute_curl_command(f"curl -X POST '{lookup_url}' -H 'Content-Type: application/json' -d '{lookup_payload}'")
    else:
        vulnerabilities.append(("Unauthorized/anonymous Firebase signup is disabled", "secure"))
    return vulnerabilities

# process apk
def process_apks(input_path, user_email):
    """Processes either a folder containing APKs or a single APK file."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(script_dir, input_path)

    if os.path.isdir(input_path):
        apk_files = [os.path.join(input_path, f) for f in os.listdir(input_path) if f.endswith('.apk')]
    elif os.path.isfile(input_path) and input_path.endswith('.apk'):
        apk_files = [input_path]
    else:
        print_to_output(f"Error: The path '{input_path}' is not a valid APK file or directory containing APKs.")
        sys.exit(1)

    for apk_path in apk_files:
        file_name = os.path.basename(apk_path)
        print_to_output(f"Processing APK: {file_name}")
        app_id, firebase_url, google_api_key, storage_bucket = extract_info_from_apk(apk_path)

        print_to_output(f"App ID: {app_id}")
        print_to_output(f"Firebase URL: {firebase_url}")
        print_to_output(f"Google API Key: {google_api_key}")
        print_to_output(f"Firebase Storage Bucket URL: {storage_bucket}")

        vulnerabilities = []
        vulnerabilities.extend(check_firebase_vulnerability(firebase_url, google_api_key, app_id))
        storage_vulns, downloadable_files = check_firebase_storage(storage_bucket)
        vulnerabilities.extend(storage_vulns)
        
        vulnerabilities.extend(check_unauthorized_signup(google_api_key, user_email))

        if downloadable_files:
            offer_file_downloads(storage_bucket, downloadable_files)
            
        vulnerable_items = [v for v in vulnerabilities if v[1] == "vulnerable"]
        secure_items = [v for v in vulnerabilities if v[1] == "secure"]
        info_items = [v for v in vulnerabilities if v[1] == "info"]
        error_items = [v for v in vulnerabilities if v[1] == "error"]
            
        if vulnerable_items:
            print_to_output("\n❌ VULNERABILITIES DETECTED:")
            for vuln, _ in vulnerable_items:
                print_to_output(f"  - {vuln}")
        
        if secure_items:
            print_to_output("\n✅ SECURE CONFIGURATIONS:")
            for vuln, _ in secure_items:
                print_to_output(f"  - {vuln}")
        
        if info_items:
            print_to_output("\nℹ️  INFORMATION:")
            for vuln, _ in info_items:
                print_to_output(f"  - {vuln}")
        
        if error_items:
            print_to_output("\n⚠️  ERRORS:")
            for vuln, _ in error_items:
                print_to_output(f"  - {vuln}")


        print_to_output("\n" + "="*50 + "\n")

# Main function
if __name__ == "__main__":
    argsparser = argparse.ArgumentParser(description="Firebase Sniper - Test Firebase security misconfigurations in APKs and Web Apps")
    argsparser.add_argument('--apk-path', type=str, help='Path to the APK file or folder containing APKs for testing')
    argsparser.add_argument('--user-email', type=str, default=f'testuser{random.randint(1000000,9999999)}@gmail.com', help='Email address to use for unauthorized signup testing (default: random email)')
    argsparser.add_argument('--output', type=str, default=OUTPUT_FILE, help='Path to the output file (default: firebase_sniper_results.txt)')
    argsparser.add_argument('--user-agent', type=str, default='BUGBOUNTY', help='Custom User-Agent for HTTP requests')
    args = argsparser.parse_args()
    if args.apk_path:
        OUTPUT_FILE = args.output
        USER_AGENT = args.user_agent
        process_apks(args.apk_path, args.user_email)
    else:
        print("No valid arguments provided. Use -h for help.")


