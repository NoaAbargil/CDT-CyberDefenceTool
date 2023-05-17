import requests
from environment_variable import *


def get_url_id(sus_URL, api_key):
    """The function receives a URL and a VirusTotal API key as parameters.
    This function is activated when the 'MurlD_main' function is called.
    This function scans the given URL and gets its ID number, if the number doesn't exist then
    a message indicating an error is returned."""
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    try:
      params = {'apikey': api_key, 'url': sus_URL}
      response = requests.post(url, data=params)
      scan_id = (response.json()['scan_id'])
    except ValueError as e:
      return ("Rate limit detected:", e)
    except Exception:  # If the try is failing for other unknown reasons
      return ("Error detected:",)
    return scan_id

def check_if_error(result):
    """The function receives either a string or a tuple as a parameter.
    This function is activated when the 'MurlD_main' function is called.
    This function checks if the supplied variable is a string or a tuple and returns
    a message accordingly."""
    if type(result) == tuple:  # In this specific code a tuple will represent an error
        return "There has been an error please try again or enter a different URL"
    return False

def final_report(scan_id, api_key):  # Returns a list that contains the final result
    """The function receives a string and a VirusTotal API key as parameters.
    This function is activated when the 'MurlD_main' function is called.
    This function makes a POST request and retrieves the VirusTotal answer. If an error
    occurs, an error message will be returned. Otherwise, the function will return a
    dictionary containing the report dictionary."""
    url = r"https://www.virustotal.com/vtapi/v2/url/report"
    try:
      params = {'apikey': api_key, 'resource': scan_id}
      response = requests.get(url, params=params)
      result_dict = response.json()
    except ValueError as e:
      return ("Rate limit detected:", e)
    except Exception:
      return ("Error detected:",)
    return result_dict


def benign_or_malicious(searchResult_dict):
    """The function receives a VirusTotal POST request dictionary as a parameter.
    This function is activated when the 'MurlD_main' function is called.
    This function checks if the site which the given dictionary represents, is malicious
    or benign and returns a string accordingly."""
    try:
        if searchResult_dict["positives"] == 0:  # The number in "positives" points to the result
          return "This site is benign- you can use it without being worried!"
        else:
          return "This site is malicious- DON'T USE IT"
    except:
        return ("Error detected:",)


def MurlD_main(sus_url):
    """The function receives a site URL as a parameter.
    This function uses a VirusTotal API key and other functions to check whether the supplied
    site, that the URL belongs too, is malicious or benign. Finally, it returns an
    appropriate string"""
    API_KEY = os.environ['VT_API']  # API key needed for the post request
    scan_id = get_url_id(sus_url, API_KEY)  # First scan in order to have the id of the site
    is_error = check_if_error(scan_id)
    if  not is_error:
      result_list = final_report(scan_id, API_KEY)
      is_error = check_if_error(result_list)
      if not is_error:
          result_string = benign_or_malicious(result_list)  # Final search result
          is_error = check_if_error(result_string)
          if not is_error:
              return result_string
          else:  # In case of an error
              return is_error
      else:  # In case of an error
          return is_error
    else:  # In case of an error
        return is_error
