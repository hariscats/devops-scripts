"""
1. Analyzing the HAR file:
   - The program reads the downloaded HAR file, which is in JSON format, and iterates through the entries 
     recorded in file.
   - It checks both the request and response headers of each entry to determine if the CSRF token is present.
   - If the CSRF token is missing in either the request or response headers, it logs these entries as potential 
     issues.

2. Reporting the findings:
   - The program prints out the URLs and details of any entries where the CSRF token is missing in the headers, 
     helping to identify potential security vulnerabilities related to CSRF protection.

By automating the process of downloading and analyzing HAR files, this program assists developers and security 
professionals in identifying and addressing CSRF token issues in web applications.
"""

import json

# Function to analyze the HAR file for CSRF token issues
def analyze_har_for_csrf(har_file_path):
    try:
        with open(har_file_path, 'r', encoding='utf-8') as file:
            har_data = json.load(file)
    except UnicodeDecodeError:
        print("Error decoding file with utf-8 encoding.")
        return

    csrf_issues = []

    for entry in har_data.get('log', {}).get('entries', []):
        request_headers = entry.get('request', {}).get('headers', [])
        response_headers = entry.get('response', {}).get('headers', [])

        # Check if CSRF token is in request headers
        csrf_in_request = any(header['name'].lower() == 'x-csrf-token' for header in request_headers)

        # Check if CSRF token is in response headers
        csrf_in_response = any(header['name'].lower() == 'x-csrf-token' for header in response_headers)

        if not csrf_in_request or not csrf_in_response:
            url = entry.get('request', {}).get('url', 'Unknown URL')
            csrf_issues.append({
                'url': url,
                'csrf_in_request': csrf_in_request,
                'csrf_in_response': csrf_in_response
            })

    if csrf_issues:
        print("Potential CSRF token issues found:")
        for issue in csrf_issues:
            print(f"URL: {issue['url']}")
            print(f"CSRF Token in Request Headers: {issue['csrf_in_request']}")
            print(f"CSRF Token in Response Headers: {issue['csrf_in_response']}")
            print("-" * 40)
    else:
        print("No CSRF token issues found.")

# Path to your downloaded HAR file
har_file_path = 'C:\\Users\\YourUsername\\Downloads\\example.har'


# Analyze the HAR file
analyze_har_for_csrf(har_file_path)
