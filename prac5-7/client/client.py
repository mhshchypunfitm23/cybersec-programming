import argparse, requests, json, time

BASE_HTTP = 'http://127.0.0.1:8080'
BASE_HTTPS = 'https://127.0.0.1:8443'

def echo(http: bool, msg: str, ca: str|None):
    base = BASE_HTTP if http else BASE_HTTPS
    url = base + ('/echo-http' if http else '/echo-https')
    if http:
        r = requests.post(url, json={'msg': msg})
    else:
        token = login('alice','secret',ca)[0]
        r = requests.post(url, json={'msg': msg}, headers={'Authorization': f'Bearer {token}'}, verify=ca)
    print(r.status_code, r.text)


def login(user, password, ca, otp=None):
    url = BASE_HTTPS + '/auth/login'
    r = requests.post(url, json={'username':user,'password':password,'otp':otp}, verify=ca)
    if r.status_code!=200:
        print('LOGIN FAIL', r.status_code, r.text); return None, r
    tok = r.json()['access_token']
    return tok, r


def whoami(token, ca):
    r = requests.get(BASE_HTTPS+'/whoami', headers={'Authorization':f'Bearer {token}'}, verify=ca)
    print(r.status_code, r.text)


def mfa_setup(user, password, ca):
    r = requests.post(BASE_HTTPS+'/auth/enable-mfa', json={'username':user,'password':password}, verify=ca)
    print(r.status_code, r.text)


def brute(user, wrong, ca):
    for i in range(int(wrong)):
        r = requests.post(BASE_HTTPS+'/auth/login', json={'username':user,'password':'bad'}, verify=ca)
        print(i, r.status_code)
        if r.status_code==429: break

if __name__=='__main__':
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    p1 = sub.add_parser('echo'); p1.add_argument('--http', action='store_true'); p1.add_argument('--https', action='store_true'); p1.add_argument('--msg', required=True); p1.add_argument('--ca')
    p2 = sub.add_parser('login'); p2.add_argument('--user', required=True); p2.add_argument('--password', required=True); p2.add_argument('--ca', required=True)
    p3 = sub.add_parser('whoami'); p3.add_argument('--token', required=True); p3.add_argument('--ca', required=True)
    p4 = sub.add_parser('mfa-setup'); p4.add_argument('--user', required=True); p4.add_argument('--password', required=True); p4.add_argument('--ca', required=True)
    p5 = sub.add_parser('mfa-login'); p5.add_argument('--user', required=True); p5.add_argument('--password', required=True); p5.add_argument('--otp', required=True); p5.add_argument('--ca', required=True)
    p6 = sub.add_parser('brute'); p6.add_argument('--user', required=True); p6.add_argument('--wrong', default=20); p6.add_argument('--ca', required=True)
    args = ap.parse_args()
    if args.cmd=='echo': echo(args.http, args.msg, args.ca)
    elif args.cmd=='login': print(login(args.user,args.password,args.ca)[0])
    elif args.cmd=='whoami': whoami(args.token,args.ca)
    elif args.cmd=='mfa-setup': mfa_setup(args.user,args.password,args.ca)
    elif args.cmd=='mfa-login': print(login(args.user,args.password,args.ca,otp=args.otp)[0])
    elif args.cmd=='brute': brute(args.user,args.wrong,args.ca)
