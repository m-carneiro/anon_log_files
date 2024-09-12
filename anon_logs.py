import base64
import glob
import re
import os
import time

secret_types = [
    "accessKey", "access_key", "access-key", "AccessKey", "AccessToken", "accessToken", "access_token", "access-token",
    "secret", "secretKey", "secret_key", "key", "auth_token", "authToken", "auth-token", "AuthToken", "auth_key", "AuthKey",
    "authKey", "auth-key", "bearer", "Bearer", "token", "Token", "password", "password_hash", "passwordHash", "pass"
]

retry_list = []
findings_list = []


def read_csv():
  csv = glob.glob('*.csv')
  for file in csv:
    if file.startswith('log'):
      with open(file, "r") as f:
        return f.readlines()


def isBase64(s):
  try:
    decoded = base64.b64decode(s, validate=True)
    return base64.b64encode(decoded).decode('ascii') == s.strip()
  except Exception:
    return False


def compare(value, list):
  for item in list:
    if item in value:
      return True
  return False


def get_secret_in_logs():
  i = 0
  try:
    logs = read_csv()
    del logs[0]
    
    for log in logs:
      log = log.split(',')
      for value in log:
        value = value.split('\n')
        for i, info in value:
          if info == '':
            del value[i]
        
        print(value)

      
      
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