import time
import os

# Define protected file path
protected_file_path = "./secret.txt"


while True:
    # get modified time
    current_modified_time = os.path.getmtime(protected_file_path)
    time.sleep(5)

    # get modified time again
    updated_modified_time = os.path.getmtime(protected_file_path)

    # Check if protected file has been modified
    if updated_modified_time != current_modified_time:
        # Trigger watch dog - Enter self destruct actions here!
        print('Unauthorised tampering detected - Self destruct activated')
        