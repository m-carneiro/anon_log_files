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


def splitter(string, maxsplit=0):
    delimiters = " ", "-", "_", ":", "="
    regex_pattern = '|'.join(map(re.escape, delimiters))
    return re.split(regex_pattern, string, maxsplit)


def sanitize(value):
  value = value.lower()
  value = value.replace('\n', '')
  value = value.replace('"', '')
  return value


def is_base64(s):
    if len(s) % 4 != 0:
        return False
    
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    if not base64_pattern.match(s):
        return False
    
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def is_jwt(token):
    if not re.match(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$', token):
        return False
    
    header, payload, signature = token.split('.')
    
    def is_base64(encoded_str):
        try:
            padding = '=' * (-len(encoded_str) % 4)
            base64.urlsafe_b64decode(encoded_str + padding)
            return True
        except (base64.binascii.Error, ValueError):
            return False
    return is_base64(header) and is_base64(payload) and is_base64(signature)


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


def get_secret_in_logs() -> list[str]:
  secrets = []
  try:
    logs = read_csv()
    for log in logs:
      log = log.split(',')
      for item in log:
        check = compare(item, secret_types)
        if check:
          new = item.split(' ')
          for k in new:
            l = k.split('\n')
            for m in l:
              if m == '-' or m == '' or m == '||' or m == ' ' or m == '\n':
                del l[l.index(m)]
              else:
                secrets.append(m)
        else:
          if compare(':', item) or compare('=', item):
            item = item.split(':')
            for i in item:       
              i = i.removesuffix('\n')
              i = i.removeprefix(' ')
              if compare(i, secret_types):
                i = i.split(' ')
                for j in i:
                  if compare(j, secret_types):
                    findings_list.append(j)
                  else:
                    retry_list.append(j)
              elif is_valid_uuid(i):
                if i not in unique_secrets:
                  unique_secrets.append(i)
              else:
                retry_list.append(i)
    return secrets                
  except Exception as e:
    print(f'Err : {e.args}')     


def classify_secrets(secrets: list[str]):
  for secret in secrets:
    items = secret.split(':')
    for i in items:
      if is_base64(i) and i != 'REST':
        if i not in findings_list:
          findings_list.append(i)
      elif is_valid_uuid(i):
        if i not in unique_secrets:
          unique_secrets.append(i)
    if is_jwt(secret):
        findings_list.append(secret)
    elif compare(secret, secret_types):
      if secret == 'Bearer' or secret == 'bearer':
        retry_list.append(secret)
      else:
        findings_list.append(secret)
    else:
      del secrets[secrets.index(secret)]


def clean_list(list: list[str]):
  list = [x for x in list if x != '']
  for item in list:
    if ":" in item:
      item = item.split(':')
      if item not in list:
        list.append(item)
  
  return list
    


def main():
  print('Initializing... \n')
  secrets = get_secret_in_logs()

  classify_secrets(secrets)
  findings_list.extend(unique_secrets)
  
  print('\n')
  print(f'Unique secrets size: {len(unique_secrets)}')
  print(f'Findings size: {len(findings_list)}')
  print(f'Retry list size: {len(retry_list)} \n')
  
  time.sleep(5)
  
  print('Findings:')
  print(clean_list(findings_list))


main()