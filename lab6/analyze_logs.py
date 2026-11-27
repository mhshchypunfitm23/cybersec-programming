import sys, json, collections

if __name__ == '__main__':
    if len(sys.argv)<2:
        print('Usage: python analyze_logs.py logs/server.jsonl'); sys.exit(1)
    p = sys.argv[1]
    events = []
    with open(p,'r',encoding='utf-8') as f:
        for line in f:
            events.append(json.loads(line))
    by_event = collections.Counter(e['event'] for e in events)
    auth_fail = [e for e in events if e['event']=='auth.fail']
    bad_hmac = [e for e in events if e['event']=='data.bad_hmac']
    invalid_token = [e for e in events if e['event']=='data.invalid_token']
    print('Events count:', dict(by_event))
    print('Auth fails:', len(auth_fail))
    offenders = collections.Counter((e.get('peer','?'), e.get('user','?')) for e in auth_fail)
    print('Top offenders:', offenders.most_common(5))
    print('Bad HMAC:', len(bad_hmac), 'Invalid token:', len(invalid_token))
