import argparse, time, statistics, requests
BASE_HTTP='http://127.0.0.1:8080'
BASE_HTTPS='https://127.0.0.1:8443'

def run(n, https, ca):
    lat=[]
    url=(BASE_HTTPS if https else BASE_HTTP)+'/echo-http'
    for _ in range(n):
        t=time.perf_counter();
        r=requests.post(url,json={'msg':'x'}, verify=ca if https else True)
        r.raise_for_status();
        lat.append((time.perf_counter()-t)*1000)
    p50=statistics.median(lat); p95=statistics.quantiles(lat, n=20)[18]
    print(f"{('HTTPS' if https else 'HTTP')}: n={n} p50={p50:.2f}ms p95={p95:.2f}ms")

if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('--n', type=int, default=100); ap.add_argument('--https', action='store_true'); ap.add_argument('--ca')
    a=ap.parse_args(); run(a.n, a.https, a.ca)
