import os
import pefile
import hashlib
import math
import requests
from bs4 import BeautifulSoup

def check_hash_legitimacy(hash_value):
    """The function receives a file's MD5 hash value as a parameter.
    This function is activated when the 'extract_features' function is called.
    This function checks whether the file's hash signature exists in the NSRL database"""
    url = "https://www.hashsets.com/nsrl/national_software_reference_library_search.php"
    payload = {
        "searchtext": hash_value,
        "searchtype": "hash",
        "Submit": "Submit"
    }
    response = requests.post(url, data=payload, verify=False)
    soup = BeautifulSoup(response.text, "html.parser")
    results = soup.find_all("td", {"class": "ResultsText"})
    if len(results) > 0:
        return True
    else:
        return False


def is_digitally_signed(file_path):
    """The function receives a file's path as a parameter.
    This function is activated when the 'extract_features' function is called.
    This function checks whether the file, which the given path belongs to, has a digital signature."""
    cmd_output = os.popen(f"""sigcheck.exe "{file_path}" """).read()
    is_signed = cmd_output.split(':\t')[1]
    if 'Signed' not in is_signed:
        return False
    return True


def calculate_signature(file_path):
    """The function receives a file's path as a parameter.
    This function is activated when the 'extract_features' function is called.
    This function calculates the MD5 hash value of the file that the given path belongs to."""
    with open(file_path, 'rb') as f:
        md5_hash = hashlib.md5()
        while chunk := f.read(8192):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()


def calculate_entropy(file_path):
    """The function receives a file's path as a parameter.
    This function is activated when the 'extract_features' function is called.
    This function calculates the entropy of the file that the given path belongs to."""
    with open(file_path, 'rb') as f:
        data = f.read()
        entropy = 0
        for byte in range(256):
            byte_count = data.count(byte)  # Calculates the frequency of each byte
            byte_prob = float(byte_count) / len(data)  # Calculates the probability of each byte occurring
            entropy -= byte_prob * math.log2(byte_prob)
        return entropy


def suspicious_imports(pe_file):
    """The function receives a PE (Portable Executable) file as a parameter.
    This function is activated when the 'extract_features' function is called.
    This function counts and returns the amount of suspicious imports that are in the given file."""
    count_suspicious_imports = 0
    import_lst = []  # For already counted imports
    for library in pe_file.DIRECTORY_ENTRY_IMPORT:  # Iterates through all the imported libraries in the PE file
        library_name = library.dll.decode().lower()
        if library_name not in import_lst:
            if library_name in ('kernel32.dll', 'advapi32.dll', 'user32.dll',
                                'ws2_32.dll', 'urlmon.dll'):  # Checks for suspicious imports
                count_suspicious_imports += 1
                import_lst.append(library.dll.decode().lower())
    return count_suspicious_imports


def suspicious_sections(pe_file):
    """The function receives a PE (Portable Executable) file as a parameter.
    This function is activated when the 'extract_features' function is called.
    This function counts and returns the amount of suspicious section names that are in the
    given file."""
    count_sus_sections = 0
    sections_lst = []  # For already counted sections
    pe_file.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])  # parse the import directory within the pe_file
    for section in pe_file.sections:
        if section:
            section_name = section.Name.decode().strip()
            if section_name not in sections_lst:
                # Check if section is executable, writable, or contains uninitialized data:
                if (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'] or
                        section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] or
                        section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']):
                    count_sus_sections += 1
                    sections_lst.append(section_name)
    return count_sus_sections


def extract_features(file_path):
    """The function receives a file's path as a parameter.
    This function is activated when the 'DMF_main' function is called.
    This function extracts features from the given file using other functions, and returns a
    dictionary containing all the features. In case of a PE format error an appropriate
    feature is added."""
    features = {'flag': False}
    try:
        pe_file = pefile.PE(file_path)  # Load the PE file
        features['size'] = os.path.getsize(file_path)  # Get file size
        features['file_md5'] = calculate_signature(file_path)
        is_legitimate_hash = check_hash_legitimacy(features['file_md5'])
        if is_legitimate_hash:  # Hash isn't in the NSRL database
            features['legitimate_hash'] = True
        else:
            features['legitimate_hash'] = False
        digitally_signed = is_digitally_signed(file_path)
        if digitally_signed:  # File isn't digitally signed
            features['digital_signature'] = True
        else:
            features['digital_signature'] = False
        count_sus_sections = suspicious_sections(pe_file)
        features['suspicious_sections'] = count_sus_sections
        count_sus_imports = suspicious_imports(pe_file)
        features['suspicious_imports'] = count_sus_imports
        entropy = calculate_entropy(file_path)  # In order to check for compressed file
        if entropy > 7.5:  # Threshold value is 7.5 bits per byte
            features['is_compressed'] = True
        else:
            features['is_compressed'] = False
        features['flag'] = True  # In case of something going wrong while checking
    except pefile.PEFormatError:  # Invalid PE file
        features['invalid_pe'] = True
    return features


def classify_file(features):
    """The function receives a file's features dictionary as a parameter.
    This function is activated when the 'DMF_main' function is called.
    This function classifies the file, which the features are his, as either benign or malicious"""
    if not features['flag']:
        return 'Something went wrong- Please try again or try entering a different file'
    elif 'invalid_pe' in features:  # Invalid PE file
        return 'Not an executable file- low-risk of file being malicious'  # Since file cannot be executed or loaded by the system
    elif features['legitimate_hash']:
        return 'The file you entered is benign- feel free to use it!'
    else:
        if features['digital_signature']:
            if features['is_compressed']:
                if int(features['size']) < 200000:
                    if features['suspicious_imports'] > 2 or features['suspicious_sections'] > 2:
                        return 'The file you entered is potentially malicious!'
                else:
                    if features['suspicious_imports'] > 3 or features['suspicious_sections'] > 3:
                        return 'The file you entered is potentially malicious!'
            else:
                if int(features['size']) < 200000:
                    if features['suspicious_imports'] > 2 and features['suspicious_sections'] > 2:
                        return 'The file you entered is potentially malicious!'
                else:
                    if features['suspicious_imports'] > 3 and features['suspicious_sections'] > 3:
                        return 'The file you entered is potentially malicious!'
        else:  # Higher chances of maliciousness
            if features['is_compressed']:
                if int(features['size']) < 200000:
                    if features['suspicious_imports'] > 0 or features['suspicious_sections'] > 0:
                        return 'The file you entered is potentially malicious!'
                else:
                    if features['suspicious_imports'] > 2 or features['suspicious_sections'] > 2:
                        return 'The file you entered is potentially malicious!'
            else:
                if int(features['size']) < 200000:
                    if features['suspicious_imports'] > 0 or features['suspicious_sections'] > 0:
                        return 'The file you entered is potentially malicious!'
                else:
                    if features['suspicious_imports'] > 3 or features['suspicious_sections'] > 3:
                        return 'The file you entered is potentially malicious!'
    return 'The file you entered is potentially benign'  # Otherwise, assume benign


def DMF_main(susFile_path):
    """The function receives a file's path as a parameter.
    This function detects and returns whether the file, which is represented by the given file path,
    is malicious or benign using two other functions."""
    features = extract_features(susFile_path)
    return classify_file(features)
