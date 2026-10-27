import json
from collections import Counter,defaultdict
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
counts=Counter();samples=defaultdict(list);files=defaultdict(set)
for folder in sorted((ROOT/'outputs/corpus_20').glob('F*')):
    coverage=json.loads((folder/'coverage_report.json').read_text(encoding='utf-8'))
    native=json.loads((folder/'parsed_native.json').read_text(encoding='utf-8'))
    records={r['source_line']:r for r in native['records']}
    for row in coverage['commands']:
        if row['status']!='extracted_unmapped':continue
        rule=row['template_rule'];counts[rule]+=1;files[rule].add(folder.name)
        if len(samples[rule])<2:
            samples[rule].append({'id':folder.name,'line':row['line'],'text':row['text'],
                'values':records[row['line']]['values'],'paths':row['normalized_paths'],
                'root':row['root_line'],'context':row['context_line']})
print('TOTAL',sum(counts.values()),'RULES',len(counts))
for rule,count in counts.most_common():
    print(json.dumps({'rule':rule,'count':count,'files':len(files[rule]),'examples':samples[rule]},ensure_ascii=False))
