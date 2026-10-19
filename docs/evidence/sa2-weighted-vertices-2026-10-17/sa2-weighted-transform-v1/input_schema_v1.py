from pathlib import Path
import json

out=Path(__file__).resolve().parent
source=out.parent/'sa2-weighted-samples-v1/weighted-packets.ai.json'
data=json.loads(source.read_text())
report={'root_type':type(data).__name__}
if isinstance(data,dict):
    report['root_keys']=list(data)
    for key,value in data.items():
        if isinstance(value,list) and value and isinstance(value[0],dict):
            report[key]={'count':len(value),'first_item_fields':{k:type(v).__name__ for k,v in value[0].items()}}
            if isinstance(value[0].get('records'),list):report[key]['first_record_fields']={k:type(v).__name__ for k,v in value[0]['records'][0].items()}
elif isinstance(data,list):report['count']=len(data);report['first_item_fields']={k:type(v).__name__ for k,v in data[0].items()}
(out/'input-schema.ai.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
