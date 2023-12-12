import requests
import logging

# Configuring logging
logging.basicConfig(level=logging.INFO)

def test_api(url, method='get', headers=None, data=None, timeout=10):
    """
    This function sends an HTTP request to the specified URL and prints the response.

    :param url: The URL of the API endpoint to be tested.
    :param method: HTTP method to use ('get', 'post', 'put', 'delete', etc.).
    :param headers: Optional HTTP headers to send with the request.
    :param data: Optional data to send with the request (for POST, PUT).
    :param timeout: Timeout for the request in seconds.
    """

    try:
        # Sending the HTTP request based on the specified method
        response = requests.request(method, url, headers=headers, data=data, timeout=timeout)

        # Checking if the request was successful
        if response.ok:
            logging.info(f"Success! Status Code: {response.status_code}")
            logging.info(f"Response Data: {response.json()}")
        else:
            logging.error(f"Failed with status code: {response.status_code}")
            logging.error(f"Response: {response.text}")

    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred: {e}")

# Example Usage
api_url = "https://jsonplaceholder.typicode.com/todos/1"
test_api(api_url)  # Basic GET request

# Example POST request (modify the URL and data as needed)
# test_api("https://jsonplaceholder.typicode.com/posts", method='post', data={'title': 'foo', 'body': 'bar', 'userId': 1})
