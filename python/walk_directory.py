import os

def list_directory_contents(path):
    """
    Lists all files and directories within the given path.

    :param path: The root directory to start listing from.
    """
    for root, dirs, files in os.walk(path):
        level = root.replace(path, '').count(os.sep)
        indent = ' ' * 4 * (level)
        print(f'{indent}{os.path.basename(root)}/')
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            print(f'{subindent}{f}')

# Example usage
path_to_list = '/Users/hariscatakovic/python-automation/'  # Replace with your directory path
list_directory_contents(path_to_list)