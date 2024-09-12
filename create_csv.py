from datetime import datetime, timedelta
import csv
import random
import uuid
import base64
import jwt

teams = ["ByteBuilders", "CodeCrafters", "DevDynamos", "HackHunters", "PixelPioneers", "CloudChasers", "DataDrifters", "ScriptSquad", "CyberSolvers"]

def create_jwt() -> str:
    payload = {
        "sub": str(uuid.uuid4()),
        "name": random.choice(read_rockyou()),
        "nickname": random.choice(read_rockyou()),
    }
    bytes = str(uuid.uuid4()).encode('ascii')
    priv_secret = base64.b64encode(bytes)
    
    return jwt.encode(payload, priv_secret, algorithm='HS256')


def read_rockyou():
    with open("rockyou.txt", "r", errors='ignore') as file:
        return file.readlines()
    

def create_secrets(secret_type: str) -> str:
    if secret_type == "accessKey" or secret_type == "access_key"  or secret_type == "access-key" or  secret_type == "AccessKey" or secret_type == "AccessToken" or secret_type == "accessToken" or secret_type == "access_token" or  secret_type == "access-token":
        cloud_provider = random.choice(["AWS", "AZ", "GCP"])
        base_secret = str(uuid.uuid4())
        hash = f"{cloud_provider}-{base_secret}"
        print('`type 1 = chosen for {secret_type}: ${hash}`')
            
        return hash
    elif secret_type == "secret" or secret_type == "secretKey" or secret_type == "secret_key" or secret_type == "key" or secret_type == "password_hash" or secret_type == "passwordHash":
        secret = random.choice(read_rockyou())
        bytes = secret.encode('ascii')
        evolved = base64.b64encode(bytes)
        hash = evolved.decode('ascii')
            
        print('`type 2 = chosen for {secret_type}: ${hash}`')
        return hash
    elif secret_type == "auth_token" or secret_type == "authToken" or secret_type == "auth-token" or secret_type == "AuthToken" or secret_type == "auth_key" or secret_type == "AuthKey" or secret_type == "authKey" or secret_type ==  "auth-key":
        hash = str(uuid.uuid4())
            
        print('`type 3 = chosen for {secret_type}: ${hash}`')
        return hash
    elif secret_type == "bearer" or secret_type == "Bearer" or secret_type == "token" or secret_type == "Token":
        hash = create_jwt()
            
        print('`type 4 = chosen for {secret_type}: ${hash}`')
        return hash
    elif secret_type == "password" or secret_type == "pass":
        hash = random.choice(read_rockyou())
            
        print('`type 5 chosen for {secret_type}: ${hash}`')
        return hash
    else:
        print('`ON ELSE => chosen for {secret_type}: ${hash}`')
        return str(uuid.uuid4())
            

def first_log_part(secret_type: str) -> str:
    if secret_type == "accessKey" or secret_type == "access_key"  or secret_type == "access-key" or  secret_type == "AccessKey" or secret_type == "AccessToken" or secret_type == "accessToken" or secret_type == "access_token" or  secret_type == "access-token":
        transaction_id = f'transactionId={random.randint(100000, 999999)}'
        dto = random.choice(["TokenRequestDTO", "TokenResponseDTO", "TokenDTO", "AccessTokenDTO"])
        team_name = random.choice(teams)
        response = random.choice([200, 201, 202, 204, 400, 401, 403, 404, 500])
        
        return f"{transaction_id} - {team_name} - {response} || {dto}(token={create_secrets(secret_type)})"
    elif secret_type == "secret" or secret_type == "secretKey" or secret_type == "secret_key" or secret_type == "key" or secret_type == "password_hash" or secret_type == "passwordHash":
        login = random.choice(["login", "signin", "authenticate", "authorize"])
        websites = random.choice(["quantumsurf.io", "bytenest.com", "nexasphere.net", "pixelforge.tech", "codepulse.dev", "cloudvoyage.org", "datawave.io", "hyperldinker.net"])
        team_name = random.choice(teams)
        response = random.choice([200, 201, 202, 204, 400, 401, 403, 404, 500])
        username = random.choice(owners)
        
        return f" REST https://{websites}/{team_name}/{login} - {response} || {username} - {create_secrets(secret_type)}"
    elif secret_type == "auth_token" or secret_type == "authToken" or secret_type == "auth-token" or secret_type == "AuthToken" or secret_type == "auth_key" or secret_type == "AuthKey" or secret_type == "authKey" or secret_type ==  "auth-key": 
        response = random.choice([200, 201, 202, 204, 400, 401, 403, 404, 500])
        websites = random.choice(["quantumsurf.io", "bytenest.com", "nexasphere.net", "pixelforge.tech", "codepulse.dev", "cloudvoyage.org", "datawave.io", "hyperldinker.net"])
        
        
        message = f""" 
[2024-09-10 12:34:56] "GET /api/v1/users/ HTTP/1.1" {response}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Host: {websites}
X-Request-Secret: {create_secrets(secret_type)}
Response Time: 13245ms
"""
        return message
    elif secret_type == "bearer" or secret_type == "Bearer" or secret_type == "token" or secret_type == "Token":
        response = random.choice([200, 201, 202, 204, 400, 401, 403, 404, 500])
        website = random.choice(["quantumsurf.io", "bytenest.com", "nexasphere.net", "pixelforge.tech", "codepulse.dev", "cloudvoyage.org", "datawave.io", "hyperldinker.net"])
        request_id = random.randint(100000, 999999)
        uri = random.choice(["login", "signin", "authenticate", "authorize"])


        
        message = f"""

[2024-09-10 12:45:23] "POST /api/v1/auth/{uri} HTTP/1.1" {response}
User-Agent: curl/7.64.1
Host: {website}
Authorization: Bearer {create_secrets(secret_type)}
X-Request-ID: {request_id}
Response Time: {random.randint(1, 100)}ms

        """
        
        return message
    elif secret_type == "password" or secret_type == "pass":
        return f"Log detected: {secret_type}={create_secrets(secret_type)}"
    else:
        return f"Log detected: {secret_type}={create_secrets(secret_type)}"


# Generate a CSV with additional log messages containing various "secret" types
fields = ['date', 'messages', 'owners']

# Define some potential "secret" types
secret_types = [
    "accessKey", "access_key", "access-key", "AccessKey", "AccessToken", "accessToken", "access_token", "access-token",
    "secret", "secretKey", "secret_key", "key", "auth_token", "authToken", "auth-token", "AuthToken", "auth_key", "AuthKey",
    "authKey", "auth-key", "bearer", "Bearer", "token", "Token", "password", "password_hash", "passwordHash", "pass"
]

owners = ["JohnDoe", "JaneSmith", "AliceJohnson", "BobWilliams"]

# Create random messages
rows = []
current_date = datetime.now()

for i in range(100):  # Generate 100 log entries
    date_str = (current_date - timedelta(days=i)).strftime('%Y-%m-%d')
    secret_type = random.choice(secret_types)
    message = first_log_part(secret_type)
    owner = random.choice(owners) 
    rows.append([date_str, message, owner])

# Write the data to a CSV file
csv_file_path = "log_messages_with_secrets.csv"

with open(csv_file_path, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(fields)
    writer.writerows(rows)

csv_file_path
