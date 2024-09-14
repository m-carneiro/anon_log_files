import base64
import glob
import re
import os
import time
import uuid

secret_types = [
    "accessKey", "access_key", "access-key", "AccessKey", "AccessToken", "accessToken", "access_token", "access-token",
    "secret", "secretKey", "secret_key", "key", "auth_token", "authToken", "auth-token", "AuthToken", "auth_key", "AuthKey",
    "authKey", "auth-key", "bearer", "Bearer", "token", "Token", "password", "password_hash", "passwordHash", "pass"
]

retry_list = []
findings_list = []
unique_secrets = []


def read_csv():
  csv = glob.glob('*.csv')
  for file in csv:
    if file.startswith('log'):
      with open(file, "r") as f:
        return f.readlines()


def is_base_64(s):
  try:
    decoded = base64.b64decode(s, validate=True)
    return base64.b64encode(decoded).decode('ascii') == s.strip()
  except Exception:
    return False
  
  
def is_valid_uuid(uuid_to_test, version=4):
    try:
        _ = uuid.UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return True


def compare(value, list):
  for item in list:
    if item in value:
      return True
  return False


def get_secret_in_logs():
  i = 0
  try:
    logs = read_csv()
    for log in logs:
      log = log.split(',')
      for item in log:
        check = compare(item, secret_types)
        if check:
          print(f'Found: {item}')
        else:
          if compare(':', item) or compare('=', item):
            item = item.split(':')
            for i in item:
              
              # TODO - Adicionar mais validações para pegar todos os tipos de secret
              if compare(i, secret_types):
                print(f'Found: {i}')
                
              # Valida o UUID e adiciona na lista de achados
              else:
                i = i.removesuffix('\n')
                i = i.removeprefix(' ')
                if is_valid_uuid(i):
                  print(f'Valid UUID: {i}')
                  if i not in unique_secrets:
                    unique_secrets.append(i)
                    
  except Exception as e:
    print(f'Err : {e}')     


def sanitize(value):
  value = value.lower()
  value = value.replace('\n', '')
  value = value.replace('"', '')
  return value

def splitter(string, maxsplit=0):
    delimiters = " ", "-", "_", ":", "="
    regex_pattern = '|'.join(map(re.escape, delimiters))
    return re.split(regex_pattern, string, maxsplit)


def main():
  print('Initializing... \n\n')
  get_secret_in_logs()
  
  time.sleep(5)
  
  print('Findings: \n')
  print(findings_list)

main()