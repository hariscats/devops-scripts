# Simple script to demonstrate OAuth flows

import requests
from urllib.parse import urlencode

# Constants: Fill these in with values obtained from the OAuth provider
CLIENT_ID = 'your-client-id'
CLIENT_SECRET = 'your-client-secret'
AUTHORIZATION_ENDPOINT = 'https://your-oauth-provider.com/auth'
TOKEN_ENDPOINT = 'https://your-oauth-provider.com/token'
REDIRECT_URI = 'http://localhost/callback'
SCOPE = 'read'

def build_auth_url():
    """Build the URL for authorizing the application."""
    query_params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': SCOPE
    }
    return f"{AUTHORIZATION_ENDPOINT}?{urlencode(query_params)}"

def get_access_token(code):
    """Exchange the authorization code for an access token."""
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response = requests.post(TOKEN_ENDPOINT, data=data)
    return response.json()

if __name__ == "__main__":
    import webbrowser
    import http.server
    import socketserver

    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            if 'code' in self.path:
                code = self.path.split('code=')[1].split('&')[0]
                token = get_access_token(code)
                self.wfile.write(f"Access Token: {token['access_token']}".encode())
            else:
                auth_url = build_auth_url()
                self.wfile.write(f'<html><head><title>OAuth Authorization</title></head>'
                                 f'<body><a href="{auth_url}">Authenticate with OAuth Provider</a></body></html>'.encode())

    with socketserver.TCPServer(("", 80), Handler) as httpd:
        print("Serving at port 80")
        webbrowser.open_new('http://localhost')
        httpd.serve_forever()
