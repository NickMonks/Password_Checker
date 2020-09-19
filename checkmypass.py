import requests
import hashlib
import sys


def requests_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'error fetching: {res.status_code}, change !')
    return res

def get_password_leaks_counts(hashes, hash_to_check):
    # We need to split it in as a tuple and then do a comprehensive tuple
   # it gets all the hash responses in the request of the url by using the text method
    hashes=(line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    #Check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    #takes only the 5 characters (in order to preserve k-anonimity)
    first5_char, tail = sha1password[:5],sha1password[5:]
    response = requests_api_data(first5_char)
    return get_password_leaks_counts(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should change it')
        else:
            print(f'{password} was not found. carry on!')
        return 'done!'

# This function will be called at the very beginning
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))