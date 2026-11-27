import json, collections, sys
p = sys.argv[1] if len(sys.argv)>1 else 'server/logs/app.jsonl'
events=[json.loads(x) for x in open(p,'r',encoding='utf-8')]
by = collections.Counter(e['msg'] for e in events)
print('Events:', dict(by))
fail = [e for e in events if e['msg'] in ('auth.fail','auth.fail.otp','rate.limit')]
print('Auth/rate issues:', len(fail))
