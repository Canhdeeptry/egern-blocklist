import requests
import yaml
import os

# URL raw của file TXT
TXT_URL = 'https://raw.githubusercontent.com/bigdargon/hostsVN/master/filters/adservers-all.txt'  # Thay thế với URL raw của bạn
YML_FILE = 'docs/blocklist.yml'

def convert_txt_to_yml():
    # Tải file TXT từ URL
    response = requests.get(TXT_URL)
    response.raise_for_status()

    # Đọc dữ liệu từ file TXT
    lines = response.text.splitlines()

    # Tạo danh sách các domain_suffix_set
    domain_suffix_set = [line.strip() for line in lines if line.strip() and not line.startswith('#')]

    # Tạo dữ liệu YML theo định dạng yêu cầu
    data = {
        'no_resolve': True,
        'domain_set': [],  # Danh sách IP có thể được thêm vào đây nếu cần
        'domain_suffix_set': domain_suffix_set
    }

    # Đảm bảo thư mục docs tồn tại
    os.makedirs(os.path.dirname(YML_FILE), exist_ok=True)

    # Ghi dữ liệu vào file YML trong thư mục docs
    with open(YML_FILE, 'w') as file:
        yaml.dump(data, file, sort_keys=False, default_flow_style=False)

if __name__ == '__main__':
    convert_txt_to_yml()
