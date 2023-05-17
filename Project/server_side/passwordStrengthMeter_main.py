import string
import passwordStrengthMeter_func as psm


def PSM_main(password):
    """The function receives a string that represents a password as a parameter.
    This function extract features from the provided password and calculates its strength
    using other function. Finally, it returns a string indicating how difficult the password
    is to crack."""
    # General needed data:
    upL = string.ascii_uppercase
    lowL= string.ascii_lowercase
    punc = string.punctuation
    digits = string.digits

    # User's password data:
    uppercase = 0
    lowercase = 0
    numbers = 0
    symbols = 0
    for char in password:  # Sorts the password's chars
        if char in upL:
            uppercase += 1
        if char in lowL:
            lowercase += 1
        if char in digits:
            numbers += 1
        if char in punc:
            symbols += 1

    repeatingUpp = psm.repeating_chars(password,upL)  # Counts using a function
    repeatingLow = psm.repeating_chars(password,lowL)  # Counts using a function
    repeatingNum = psm.repeating_chars(password,digits)  # Counts using a function

    consecutive_dict = psm.consecutive_letters(password)
    consecutiveUpp = consecutive_dict['scoreUp']  # Counts using a function
    consecutiveLow = consecutive_dict['scoreLow']  # Counts using a function

    seq_dict = psm.ascii_sequence(password)
    sequentialL = seq_dict['letters']  # Counts using a function
    sequentialNum = seq_dict['digits']  # Counts using a function


    pass_complexity_dict = {} # To sum up all the details
    pass_complexity_dict = psm.password_condition(pass_complexity_dict,len(password), "length", 8)
    pass_complexity_dict = psm.password_condition(pass_complexity_dict, uppercase, "uppercase", 2)
    pass_complexity_dict = psm.password_condition(pass_complexity_dict, lowercase, "lowercase", 4)
    pass_complexity_dict = psm.password_condition(pass_complexity_dict, numbers, "numbers", 5)
    pass_complexity_dict = psm.password_condition(pass_complexity_dict, symbols, "symbols", 1)
    pass_complexity_dict = psm.password_condition(pass_complexity_dict, len(repeatingUpp), "repeatUppL", 2, '>')
    pass_complexity_dict = psm.password_condition(pass_complexity_dict, len(repeatingLow), "repeatLowL", 1, '>')
    pass_complexity_dict = psm.password_condition(pass_complexity_dict, len(repeatingNum), "repeatNum", 0, '>')
    pass_complexity_dict = psm.password_condition(pass_complexity_dict, consecutiveUpp, "consecutUppL", 0,'>')
    pass_complexity_dict = psm.password_condition(pass_complexity_dict, consecutiveLow, "consecutLowL", 0,'>')
    pass_complexity_dict = psm.password_condition(pass_complexity_dict, sequentialL, "sequenceLet", 2, '>')
    pass_complexity_dict = psm.password_condition(pass_complexity_dict, sequentialNum, "sequenceNum", 2, '>')

    pass_complexity_lst = list(pass_complexity_dict.values())
    password_grade = psm.final_pass_grade(pass_complexity_lst, len(password))

    # Printing a suitable message for the customer:
    if password_grade >= 85:
        return ("Your password is very strong --> Good Job!")
    elif password_grade >= 72:
        return ("Your password is strong")
    elif password_grade >= 65:
        return ("Your password is OK, but you should make it stronger!")
    elif password_grade >= 45:
        return("Your password is weak --> don't use this password, try better!")
    else:  # Password_grade < 45
        return("Your password is very weak- Do NOT use it!!!")
