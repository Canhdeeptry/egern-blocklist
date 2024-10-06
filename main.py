import requests
import yaml
import os

TXT_URL = ['https://abpvn.com/filter/abpvn-F2blen.txt',
           'https://raw.githubusercontent.com/bigdargon/hostsVN/master/filters/adservers-all.txt'
]  
YML_FILE = 'docs/blocklist.yml'

def convert_txt_to_yml():
    
    response = requests.get(TXT_URL)
    response.raise_for_status()

    
    lines = response.text.splitlines()

    domain_set = []  
    domain_suffix_set = []

    
    for line in lines:
        line = line.strip()
        if line and not line.startswith('!'):  
            if line.startswith('||'):
                domain_suffix = line[2:].split('^')[0]  
                domain_suffix_set.append(domain_suffix)
            elif line.startswith('||'):
                pass
    
    data = {
        'no_resolve': True,
        'domain_set': domain_set,
        'domain_suffix_set': domain_suffix_set
    }

    os.makedirs(os.path.dirname(YML_FILE), exist_ok=True)

    with open(YML_FILE, 'w') as file:
        yaml.dump(data, file, sort_keys=False, default_flow_style=False)

if __name__ == '__main__':
    convert_txt_to_yml()
