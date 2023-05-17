import os
import string

def UP_main():
    """The function doesn't receive any parameters.
    This function checks for patches that needs update, and updates the once that can be
    updated. The function finally outputs the id number of the patches that it was unable
    to update, if any."""
    patchID_list = []  # Empty list to store the Ids
    command_output = os.popen("winget upgrade --accept-source-agreements").read()  # Getting patches info using the cmd
    winget_lines = command_output.split('\n')  # Split the input string into individual lines
    for line in winget_lines:  # iterate through each line in the output
        # split the line into individual words
        words_lst = line.split()
        for word in words_lst:  # Extract the Id and
            if "PyCharm" not in word:
                letters = string.ascii_letters
                if '.' in word:  # Check if the word has the ID required tav--> '.'
                    dot_index = word.index('.')
                    if dot_index != len(word) - 1 and dot_index != 0:
                        if word[dot_index - 1] in letters and word[dot_index + 1] in letters:
                            patchID_list.append(word)  # Append Id to the list
                            break  # The word has been successfully written
            else:
                break
    fails_id = []  # Like many situations: the app is open, it needs to be handly updated and so on...
    append_failed_flag = False  # To avoid appending the same app Id twice
    for id in patchID_list:  # Executing the update action using the cmd:
        try:
            upgrade_status = os.system(f"winget upgrade --accept-source-agreements --id {id}")  # For source level agreements
            if upgrade_status != 0:  # Any non-zero status code values indicates an error
                fails_id.append(id)
                append_failed_flag = True
        except OSError:  # Raised when an os specific system function returns a system-related error
            fails_id.append(id)
            append_failed_flag = True
        try:
            upgrade_status = os.system(f"winget upgrade --accept-package-agreements --id {id}")  # For package level agreements
            if upgrade_status != 0 and not append_failed_flag:  # Any non-zero status code values indicates an error
                fails_id.append(id)
        except OSError:  # Raised when an os specific system function returns a system-related error
            if not append_failed_flag:
                fails_id.append(id)
        append_failed_flag = False
    command_output = command_output.replace('¦', '  ')  # Prepare it for figuring out the names of the apps we failed to update
    command_output = command_output.replace('…', '  ').replace('(x', '  ').replace('- ','  ')
    winget_lines = command_output.split('\n')  # Split the input string into individual lines
    fails_names_lst = []
    for ID in fails_id:
        char_index = 0  # Reset variable
        app_name = ""  # Reset variable
        for line in winget_lines:
            if ID in line:
                for char in line:
                    if char == " " and line[char_index + 1] == " ":
                        break  # Since the name for this specific ID is successfully complete
                    app_name += char
                    char_index += 1
                fails_names_lst.append(app_name)
                break  # The name for this ID is complete, therefore this for loop
    return fails_names_lst
