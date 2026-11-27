import json, sys, collections, time

if __name__ == '__main__':
    p = sys.argv[1] if len(sys.argv)>1 else 'logs/events.jsonl'
    events = [json.loads(x) for x in open(p,'r',encoding='utf-8')]
    by = collections.Counter(e['event'] for e in events)
    print('Events:', dict(by))
    denies = [e for e in events if e.get('action')=='deny']
    top_src = collections.Counter(tuple(e.get('src',[])) for e in denies).most_common(5)
    print('Denied count:', len(denies))
    print('Top denied sources:', top_src)
