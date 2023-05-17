import string


# General needed data
upL = string.ascii_uppercase
lowL = string.ascii_lowercase
digits = string.digits


# All the functions that belong to the Password Strength Meter security engine:
def repeating_chars(password, kind):
    """The function receives a password and a chars kind(digits/uppercase letters/lowercase
    letters) as parameters.
    This function checks for repeating characters in the given password that belong to the category
    specified which . It then returns a list of characters that repeat more than two times
    in the password."""
    count = 0
    lst = []
    for char1 in password:
        if (char1 in kind) and (char1 not in lst):  # Counting only number & uppercase & lowercase
            for char2 in password:
                if char2 == char1:
                    count += 1
            if count > 2:  # Only if char repeats itself more than 2 times
                lst.append(char1)
            count = 0
    return lst


def consecutive_letters(password):
    """The function receives a password as a parameter.
    This function checks for consecutive keyboard letters in the given password, and returns
    a dictionary with the amount of triplet consecutive keyboard sequences for upper
    and lower case letters."""
    a = "qwertyuiop"  # Lower case
    b = "asdfghjkl"
    c = "ASDFGHJKL"
    A = "QWERTYUIOP"  # Upper case
    B = "ASDFGHJKL"
    C = "ASDFGHJKL"
    score = {"scoreUp": 0, "scoreLow": 0}
    for i in range(len(password) - 2):
        s = password[i:i + 3]  # Counts only triplet sequences
        if s in upL:
            if s in A or s in B or s in C:
                score["scoreUp"] += 1
        if s in upL:
            if s in a or s in b or s in c:
                score["scoreLow"] += 1
    return score


def mark_as_sequence(countSeq, char, sequences_data):
    """The function receives the following parameters: amount of characters in some sequence, a
    char,and dictionary containing data about sequences found so far.
    This function is activated when the 'ascii_sequence' function is called.
    This function marks the given sequence of characters as either a sequence of letters
    or digits and creates a new key and value in the supplied dictionary."""
    if char in digits:
        sequences_data['digits'] += countSeq
    else:
        sequences_data['letters'] += countSeq
    return sequences_data


def ascii_sequence(password):
    """The function receives a password as parameter.
    This function checks for sequential numbers and letters in a password and marks them as
    either a sequence of letters or digits using other function. at last, it returns a
    dictionary containing the number of letters and digits found as a part of a sequence."""
    sequences_data = {'letters': 0, 'digits': 0}  # One sequence of each kind is enough to determine the weakness
    char = str(password[0])
    countSeq = 1
    for char2 in password[1::]:
        char_ord = ord(char)  # Finds sequence according to their ascii number
        if char_ord + 1 == ord(str(char2)):  # Checking if it's truly a sequence
            countSeq += 1
            if password.index(char2) + 1 == len(password):
                sequences_data = mark_as_sequence(countSeq, char, sequences_data)
        else:
            if countSeq > 2:  # Only if sequence is bigger than 2
                sequences_data = mark_as_sequence(countSeq, char, sequences_data)
            countSeq = 1  # Get ready for a new sequence
        char = char2
    return sequences_data


def password_condition(complexity_dict, detail_num, subject_name, condition_num, char_condition='<'):
    """The function receives the following parameters: a dictionary containing all the features
    extracted from a password,a specific feature value, a dictionary key, a number that is
    checked against 'detail_num', and a char representing a kind of condition('<' by default).
    This function updates the given value in the given dictionary according to a condition
    that is built from the supplied data."""
    if char_condition == '<':  # '<' for specific conditions
        if detail_num < condition_num:
            complexity_dict[subject_name] = 0  # 0 means it's a weakness
        else:
            complexity_dict[subject_name] = 1  # 1 means it's a strength
    if char_condition == '>':  # '>' for specific conditions
        if detail_num > condition_num:
            complexity_dict[subject_name] = 0
        else:
            complexity_dict[subject_name] = 1
    return complexity_dict


def final_pass_grade(complex_lst, passwordLen):
    """The function receives a list which represents a password's weaknesses and a number as parameters.
    This function calculates and returns a score of a password based on the password's
    weaknesses that the values in the given list indicates."""
    pass_grade = len(complex_lst) * 8  # Starting grade is 96(=12*8)
    for i in range(len(complex_lst)):
        if complex_lst[i] == 0:  # Minus points according to index: 1:-20, 2->4:-15, 5:-5, 6:-8, 7->8:-10, 9:-5, 10->11:-10, 12:-15
            if i == 0:  # --> length
                pass_grade -= 20
            elif (3 >= i >= 1) or i == 11:  # --> lowercase,uppercase,numbers,sequenceNum
                pass_grade -= 15
            elif i == 4 or i == 8:  # --> Symbols, consecutUppL
                pass_grade -= 5
            elif i == 5:  # --> repeatUppL
                pass_grade -= 8
            elif (7 >= i >= 6) or (10 >= i >= 9):  # -->repeatUppL,repeatLowL,consecutLowL,sequenceLet
                pass_grade -= 10
    if passwordLen >= 10:  # Add points due to the length--> bonus points
        pass_grade += (passwordLen-8)*2.5
    return pass_grade
