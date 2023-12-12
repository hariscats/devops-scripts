import requests

def test_api(url):
    """
    This function sends a GET request to the specified URL and prints the response.

    :param url: The URL of the API endpoint to be tested.
    """

    # Sending a GET request to the API
    response = requests.get(url)

    # Checking if the request was successful
    if response.status_code == 200:
        print("Success!")
        print("Response Data:", response.json())  # Print the JSON response
    else:
        print("Failed with status code:", response.status_code)
        print("Response:", response.text)

# Example URL of a public API
api_url = "https://jsonplaceholder.typicode.com/todos/1"

# Calling the function with the API URL
test_api(api_url)
