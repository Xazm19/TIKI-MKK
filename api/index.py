from flask import Flask, request, jsonify, g, Response
import json
import os
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from functools import wraps
import re
import html
import redis
import hashlib
import time
import secrets
import string
import random
from concurrent.futures import ThreadPoolExecutor
import logging
from dateutil.parser import parse as parse_date
import threading
from copy import deepcopy

logging.basicConfig(level=logging.ERROR)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_urlsafe(32)

# Redis configuration (keep as is)
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True, socket_connect_timeout=5)

# JSON file paths
DATA_DIR = 'data'
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

JSON_FILES = {
    'users': os.path.join(DATA_DIR, 'users.json'),
    'services': os.path.join(DATA_DIR, 'services.json'),
    'tikis': os.path.join(DATA_DIR, 'tikis.json'),
    'counters': os.path.join(DATA_DIR, 'counters.json'),
    'invitations': os.path.join(DATA_DIR, 'invitations.json'),
    'wilayas': os.path.join(DATA_DIR, 'wilayas.json'),
    'servicesTypes': os.path.join(DATA_DIR, 'servicesTypes.json')
}

# Thread lock for file operations
file_lock = threading.Lock()

# JSON Database Class
class JSONDatabase:
    def __init__(self):
        self.initialize_files()
    
    def initialize_files(self):
        # Initialize wilayas
        wilayas = [
            {"name": "1. Adrar"},
            {"name": "2. Chlef"},
            {"name": "3. Laghouat"},
            {"name": "4. Oum El Bouaghi"},
            {"name": "5. Batna"},
            {"name": "6. Béjaïa"},
            {"name": "7. Biskra"},
            {"name": "8. Béchar"},
            {"name": "9. Blida"},
            {"name": "10. Bouira"},
            {"name": "11. Tamanrasset"},
            {"name": "12. Tébessa"},
            {"name": "13. Tlemcen"},
            {"name": "14. Tiaret"},
            {"name": "15. Tizi Ouzou"},
            {"name": "16. Alger"},
            {"name": "17. Djelfa"},
            {"name": "18. Jijel"},
            {"name": "19. Sétif"},
            {"name": "20. Saïda"},
            {"name": "21. Skikda"},
            {"name": "22. Sidi Bel Abbès"},
            {"name": "23. Annaba"},
            {"name": "24. Guelma"},
            {"name": "25. Constantine"},
            {"name": "26. Médéa"},
            {"name": "27. Mostaganem"},
            {"name": "28. M'Sila"},
            {"name": "29. Mascara"},
            {"name": "30. Ouargla"},
            {"name": "31. Oran"},
            {"name": "32. El Bayadh"},
            {"name": "33. Illizi"},
            {"name": "34. Bordj Bou Arréridj"},
            {"name": "35. Boumerdès"},
            {"name": "36. El Tarf"},
            {"name": "37. Tindouf"},
            {"name": "38. Tissemsilt"},
            {"name": "39. El Oued"},
            {"name": "40. Khenchela"},
            {"name": "41. Souk Ahras"},
            {"name": "42. Tipaza"},
            {"name": "43. Mila"},
            {"name": "44. Aïn Defla"},
            {"name": "45. Naâma"},
            {"name": "46. Aïn Témouchent"},
            {"name": "47. Ghardaïa"},
            {"name": "48. Relizane"},
            {"name": "49. Timimoun"},
            {"name": "50. Bordj Badji Mokhtar"},
            {"name": "51. Ouled Djellal"},
            {"name": "52. Béni Abbès"},
            {"name": "53. In Salah"},
            {"name": "54. In Guezzam"},
            {"name": "55. Touggourt"},
            {"name": "56. Djanet"},
            {"name": "57. El M'Ghair"},
            {"name": "58. El Meniaa"}
        ]

        # Initialize service types
        allservicestypes = [
            {
                "name": "Doctor",
                "type": "doctor",
                "iconPath": "assets/icons/stickers/icons8-stethoscope-100.png",
                "colorValue": 4281558685,
                "available": True
            },
            {
                "name": "Dentist",
                "type": "dentist",
                "iconPath": "assets/icons/stickers/icons8-tooth-100.png",
                "colorValue": 4278222848,
                "available": True
            },
            {
                "name": "Barber",
                "type": "barber",
                "iconPath": "assets/icons/stickers/icons8-barber-100.png",
                "colorValue": 4281348144,
                "available": True
            },
            {
                "name": "Mechanic",
                "type": "mechanic",
                "iconPath": "assets/icons/stickers/icons8-car-service-100.png",
                "colorValue": 4294961979,
                "available": True
            },
            {
                "name": "Painter",
                "type": "painter",
                "iconPath": "assets/icons/stickers/icons8-paint-roller-100.png",
                "colorValue": 4278238421,
                "available": True
            },
            {
                "name": "Plumber",
                "type": "plumber",
                "iconPath": "assets/icons/stickers/icons8-pipe-100.png",
                "colorValue": 4285594436,
                "available": True
            },
            {
                "name": "Electrician",
                "type": "electrician",
                "iconPath": "assets/icons/stickers/icons8-disconnected-100.png",
                "colorValue": 4294144000,
                "available": True
            },
            {
                "name": "Fixer",
                "type": "fixer",
                "iconPath": "assets/icons/stickers/icons8-tool-100.png",
                "colorValue": 4281348144,
                "available": True
            },
            {
                "name": "Lavage",
                "type": "lavage",
                "iconPath": "assets/icons/stickers/icons8-automatic-car-wash-100.png",
                "colorValue": 4278238421,
                "available": True
            },
            {
                "name": "Beauty",
                "type": "beauty",
                "iconPath": "assets/icons/stickers/icons8-hello-kitty-100.png",
                "colorValue": 4294956775,
                "available": True
            },
            {
                "name": "Perfume",
                "type": "perfume",
                "iconPath": "assets/icons/stickers/icons8-perfume-100.png",
                "colorValue": 4282339765,
                "available": True
            },
            {
                "name": "Delivery",
                "type": "delivery",
                "iconPath": "assets/icons/stickers/icons8-holding-box-100.png",
                "colorValue": 4281545523,
                "available": True
            },
            {
                "name": "Box Service",
                "type": "box",
                "iconPath": "assets/icons/stickers/icons8-package-50.png",
                "colorValue": 4279903102,
                "available": True
            }
        ]

        # Initialize files if they don't exist
        if not os.path.exists(JSON_FILES['wilayas']):
            self.write_file('wilayas', wilayas)
        
        if not os.path.exists(JSON_FILES['servicesTypes']):
            self.write_file('servicesTypes', allservicestypes)

        # Initialize other files
        for collection in ['users', 'services', 'tikis', 'counters', 'invitations']:
            if not os.path.exists(JSON_FILES[collection]):
                self.write_file(collection, [])
    
    def read_file(self, collection):
        try:
            with file_lock:
                if os.path.exists(JSON_FILES[collection]):
                    with open(JSON_FILES[collection], 'r', encoding='utf-8') as f:
                        return json.load(f)
                return []
        except Exception as e:
            print(f"Error reading {collection}: {e}")
            return []
    
    def write_file(self, collection, data):
        try:
            with file_lock:
                with open(JSON_FILES[collection], 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2, default=str)
                return True
        except Exception as e:
            print(f"Error writing {collection}: {e}")
            return False
    
    def generate_id(self):
        return secrets.token_urlsafe(16)
    
    def find_one(self, collection, query):
        data = self.read_file(collection)
        for item in data:
            match = True
            for key, value in query.items():
                if key not in item:
                    match = False
                    break
                if isinstance(value, dict):
                    # Handle regex queries
                    if '$regex' in value:
                        pattern = value['$regex']
                        options = value.get('$options', '')
                        flags = re.IGNORECASE if 'i' in options else 0
                        if not re.search(pattern, str(item[key]), flags):
                            match = False
                            break
                elif item[key] != value:
                    match = False
                    break
            if match:
                return item
        return None
    
    def find(self, collection, query=None, projection=None, skip=0, limit=None, sort=None):
        data = self.read_file(collection)
        results = []
        
        for item in data:
            match = True
            if query:
                for key, value in query.items():
                    if key not in item:
                        match = False
                        break
                    
                    if isinstance(value, dict):
                        # Handle special operators
                        if '$regex' in value:
                            pattern = value['$regex']
                            options = value.get('$options', '')
                            flags = re.IGNORECASE if 'i' in options else 0
                            if not re.search(pattern, str(item[key]), flags):
                                match = False
                                break
                        elif '$gte' in value:
                            if isinstance(item[key], str):
                                item_date = datetime.fromisoformat(item[key].replace('Z', '+00:00'))
                                query_date = value['$gte']
                                if item_date < query_date:
                                    match = False
                                    break
                            elif item[key] < value['$gte']:
                                match = False
                                break
                        elif '$lt' in value:
                            if isinstance(item[key], str):
                                item_date = datetime.fromisoformat(item[key].replace('Z', '+00:00'))
                                query_date = value['$lt']
                                if item_date >= query_date:
                                    match = False
                                    break
                            elif item[key] >= value['$lt']:
                                match = False
                                break
                        elif '$nin' in value:
                            if item[key] in value['$nin']:
                                match = False
                                break
                    elif item[key] != value:
                        match = False
                        break
            
            if match:
                # Apply projection
                result_item = deepcopy(item)
                if projection:
                    projected_item = {}
                    for field, include in projection.items():
                        if include and field in result_item:
                            projected_item[field] = result_item[field]
                    result_item = projected_item
                
                results.append(result_item)
        
        # Apply sorting
        if sort:
            for field, direction in sort:
                reverse = direction == -1
                try:
                    results.sort(key=lambda x: x.get(field, ''), reverse=reverse)
                except:
                    pass
        
        # Apply skip and limit
        if skip:
            results = results[skip:]
        if limit:
            results = results[:limit]
        
        return results
    
    def insert_one(self, collection, document):
        data = self.read_file(collection)
        document['_id'] = self.generate_id()
        
        # Check for unique constraints
        if collection == 'users':
            if any(item.get('email') == document.get('email') for item in data):
                raise Exception('duplicate key error: email')
            if any(item.get('invitation_code') == document.get('invitation_code') for item in data):
                raise Exception('duplicate key error: invitation_code')
        
        if collection == 'services':
            if any(item.get('email') == document.get('email') for item in data):
                raise Exception('duplicate key error: email')
        
        if collection == 'tikis':
            # Check unique constraints for tikis
            for item in data:
                if (item.get('serviceID') == document.get('serviceID') and 
                    item.get('date') == document.get('date') and 
                    item.get('clientID') == document.get('clientID')):
                    raise Exception('duplicate key error: serviceID_date_clientID')
        
        if collection == 'invitations':
            if any(item.get('code') == document.get('code') for item in data):
                raise Exception('duplicate key error: code')
        
        data.append(document)
        if self.write_file(collection, data):
            return type('InsertResult', (), {'inserted_id': document['_id']})()
        return None
    
    def update_one(self, collection, query, update):
        data = self.read_file(collection)
        for i, item in enumerate(data):
            match = True
            for key, value in query.items():
                if key not in item or item[key] != value:
                    match = False
                    break
            
            if match:
                if '$set' in update:
                    for key, value in update['$set'].items():
                        data[i][key] = value
                
                if '$inc' in update:
                    for key, value in update['$inc'].items():
                        data[i][key] = data[i].get(key, 0) + value
                
                if self.write_file(collection, data):
                    return type('UpdateResult', (), {'matched_count': 1, 'modified_count': 1})()
                break
        
        return type('UpdateResult', (), {'matched_count': 0, 'modified_count': 0})()
    
    def count_documents(self, collection, query=None):
        results = self.find(collection, query)
        return len(results)
    
    def find_one_and_update(self, collection, query, update, upsert=False, return_document=True):
        data = self.read_file(collection)
        
        for i, item in enumerate(data):
            match = True
            for key, value in query.items():
                if key not in item or item[key] != value:
                    match = False
                    break
            
            if match:
                if '$inc' in update:
                    for key, value in update['$inc'].items():
                        data[i][key] = data[i].get(key, 0) + value
                
                if self.write_file(collection, data):
                    return data[i]
                return None
        
        # If not found and upsert is True
        if upsert:
            new_doc = deepcopy(query)
            new_doc['_id'] = self.generate_id()
            
            if '$inc' in update:
                for key, value in update['$inc'].items():
                    new_doc[key] = value
            
            data.append(new_doc)
            if self.write_file(collection, data):
                return new_doc
        
        return None

# Initialize JSON database
db = JSONDatabase()

executor = ThreadPoolExecutor(max_workers=20)

def get_cache_key(key_type, *args):
    return f"{key_type}:{':'.join(str(arg) for arg in args)}"

def cache_get(key):
    try:
        return redis_client.get(key)
    except:
        return None

def cache_set(key, value, ttl=300):
    try:
        redis_client.setex(key, ttl, value)
    except:
        pass

def cache_del(key):
    try:
        redis_client.delete(key)
    except:
        pass

def hash_pwd(pwd):
    return bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt(rounds=12))

def check_pwd(pwd, hashed):
    return bcrypt.checkpw(pwd.encode('utf-8'), hashed)

def generate_invitation_code():
    numbers = ''.join(random.choices(string.digits, k=16))
    return f"TIKI-ROBY-{numbers[:4]}-{numbers[4:8]}-{numbers[8:12]}-{numbers[12:16]}"

def gen_token(uid, utype):
    payload = {
        'uid': str(uid),
        'utype': utype,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow(),
        'jti': secrets.token_urlsafe(16)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def rate_limit(max_requests=10, window=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            uid = getattr(g, 'uid', request.remote_addr)
            key = f"rate_limit:{f.__name__}:{uid}"
            
            try:
                current = redis_client.get(key)
                if current and int(current) >= max_requests:
                    return jsonify({'error': 'Rate limit exceeded'}), 429
                
                pipe = redis_client.pipeline()
                pipe.incr(key)
                pipe.expire(key, window)
                pipe.execute()
            except:
                pass
            
            return f(*args, **kwargs)
        return decorated
    return decorator

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            cache_key = get_cache_key('token', hashlib.md5(token.encode()).hexdigest())
            cached_data = cache_get(cache_key)
            
            if cached_data:
                uid, utype = cached_data.split(':')
            else:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                uid = data['uid']
                utype = data['utype']
                cache_set(cache_key, f"{uid}:{utype}", 3600)
            
            g.uid = uid
            g.utype = utype
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(uid, utype, *args, **kwargs)
    return decorated

def validate_input(data, fields):
    if not data:
        return None
    
    sanitized = {}
    for field in fields:
        if field in data:
            value = data[field]
            if isinstance(value, str):
                value = html.escape(value.strip())
                if len(value) > 500:
                    return None
                
                if field == 'email':
                    if not re.match(r'.+@.+\..+', value):
                        return None
                elif field in ['phone_number', 'phone_number']:
                    if not re.match(r'^\+?[0-9]{8,15}$', value):
                        return None
                elif field == 'password':
                    if len(value) < 8 or len(value) > 128:
                        return None
                elif field == 'invitation_code':
                    if not re.match(r'^TIKI-ROBY-\d{4}-\d{4}-\d{4}-\d{4}$', value):
                        return None
                elif field == 'date':
                    try:
                        datetime.strptime(value, '%Y-%m-%d')
                    except ValueError:
                        return None
                
                sanitized[field] = value
            elif isinstance(value, int):
                if field == 'age' and (value < 13 or value > 120):
                    return None
                sanitized[field] = value
            else:
                sanitized[field] = value
    
    return sanitized

def get_next_tiki_num(sid, date):
    cache_key = get_cache_key('tiki_num', sid, date)
    cached_num = cache_get(cache_key)
    
    if cached_num:
        try:
            num = int(cached_num) + 1
            cache_set(cache_key, str(num), 3600)
            return num
        except Exception as e:
            print("Error parsing cached number:", e)
    
    try:
        result = db.find_one_and_update(
            'counters',
            {'_id': f"{sid}:{date}"},
            {'$inc': {'count': 1}},
            upsert=True,
            return_document=True
        )
        if result and 'count' in result:
            num = result['count']
            cache_set(cache_key, str(num), 3600)
            return num
        
    except Exception as e:
        print("Error incrementing counter:", e)
    
    try:
        count = db.count_documents('tikis', {'serviceID': sid, 'date': date})
        return count + 1
    except Exception as e:
        print("Fallback count_documents failed:", e)
        return None

def check_monthly_limit(uid):
    cache_key = get_cache_key('monthly_limit', uid)
    cached_count = cache_get(cache_key)
    
    if cached_count:
        return int(cached_count) < 30
    
    start = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (start + timedelta(days=32)).replace(day=1)
    
    count = db.count_documents('tikis', {
        'clientId': uid,
        'createdAt': {'$gte': start, '$lt': end}
    })
    
    cache_set(cache_key, str(count), 3600)
    return count < 30

def check_daily_limit(uid, sid, date):
    cache_key = get_cache_key('daily_limit', uid, sid, date)
    cached_exists = cache_get(cache_key)
    
    if cached_exists == 'true':
        return False
    elif cached_exists == 'false':
        return True
    
    exists = db.count_documents('tikis', {
        'clientId': uid,
        'serviceID': sid,
        'date': date
    }) > 0
    
    cache_set(cache_key, 'true' if exists else 'false', 86400)
    return not exists

@app.before_request
def before_request():
    g.start_time = time.time()

@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.route("/servicesType", methods=["GET"])
def get_services_types():
    services = db.read_file('servicesTypes')
    return jsonify(services)

@app.route("/wilayas", methods=["GET"])
def get_wilayas():
    wilayas = db.read_file('wilayas')
    return jsonify(wilayas)

VERIFICATION_CODE_EXPIRE = 300  # 5 minutes

@app.route('/send-verification', methods=['POST'])
@rate_limit(max_requests=3, window=60)
def send_verification():
    data = request.get_json()
    email = data.get('email')
    
    if not email or not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return jsonify({'error': 'Invalid email'}), 400
    
    code = ''.join(random.choices('0123456789', k=6))
 
    redis_client.setex(f'verification:{email}', VERIFICATION_CODE_EXPIRE, code)  
    
    print(f"Verification code for {email}: {code}")  # Remove in production
    
    return jsonify({'success': True}), 200

@app.route('/verify-code', methods=['POST'])
@rate_limit(max_requests=5, window=60)
def verify_code():
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')
    
    if not email or not code:
        return jsonify({'error': 'Email and code required'}), 400
   
    stored_code = redis_client.get(f'verification:{email}')
    
    if not stored_code or stored_code != code:
        return jsonify({'error': 'Invalid or expired code'}), 400
   
    redis_client.setex(f'verified:{email}', 3600*24, 'true')  # 24 hour expiration
    
    return jsonify({'success': True}), 200

@app.route('/u/reg', methods=['POST'])
@rate_limit(max_requests=5, window=300)
def u_reg():
    data = request.get_json()
    fields = ['email', 'password', 'name', 'wilaya']
    clean_data = validate_input(data, fields)

    if not clean_data or len(clean_data) < 4:
        return jsonify({'error': 'Invalid input'}), 400
    
    try:
        user_invitation_code = generate_invitation_code()
        
        user_data = {
            'email': clean_data['email'],
            'password': hash_pwd(clean_data['password']).decode('utf-8'),
            'name': clean_data['name'],
            'wilaya': clean_data['wilaya'],
            'age': '',
            'gender': '',
            'phone_number': 0,
            'invitation_code': user_invitation_code,
            'points': 0,
            'used_invitation_code': '',
            'createdAt': datetime.now().isoformat(),
            'status': 'active',
            'type':'user',
            'address':'address',
        }
        
        result = db.insert_one('users', user_data)
        
        invitation_data = {
            'code': user_invitation_code,
            'owner_id': str(result.inserted_id),
            'created_at': datetime.now().isoformat(),
            'used_by': None
        }
        
        db.insert_one('invitations', invitation_data)
        
        token = gen_token(result.inserted_id, 'user')
        
        return jsonify({
            'token': token,
            'uid': str(result.inserted_id),
            'invitation_code': user_invitation_code,
            'points': 0
        }), 201
        
    except Exception as e:
        if 'duplicate key' in str(e):
            return jsonify({'error': 'Email already exists'}), 409
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/u/login', methods=['POST'])
@rate_limit(max_requests=10, window=300)
def u_login():
    data = request.get_json()
    clean_data = validate_input(data, ['email', 'password'])
    
    if not clean_data:
        return jsonify({'error': 'Invalid input'}), 400
    
    user = db.find_one('users', {'email': clean_data['email']})
    
    if user and user.get('status') == 'active' and check_pwd(clean_data['password'], user['password'].encode('utf-8')):
        token = gen_token(user['_id'], 'user')
        return jsonify({
            'token': token,
            'uid': str(user['_id']),
            'invitation_code': user.get('invitation_code'),
            'points': user.get('points', 0)
        }), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/u/update-profile/<owner_id>', methods=['PUT'])
@auth_required
def update_profile(uid, utype, owner_id):
    user = db.find_one('users', {'_id': owner_id})

    now = datetime.now(timezone.utc)
    last_edited = user.get('editedAt')

    if last_edited:
        if isinstance(last_edited, str):
            last_edited = datetime.fromisoformat(last_edited.replace('Z', '+00:00'))
        if last_edited.tzinfo is None:
            last_edited = last_edited.replace(tzinfo=timezone.utc)

    if last_edited and (now - last_edited).days < 7:
        return jsonify({'error': 'You can edit your profile once per week'}), 403

    data = request.json
    data['editedAt'] = now.isoformat()

    db.update_one('users', {'_id': owner_id}, {'$set': data})
    return jsonify({'message': 'Profile updated'}), 200

@app.route('/u/use-invitation', methods=['POST'])
@auth_required
@rate_limit(max_requests=5, window=300)
def use_invitation(uid, utype):
    if utype != 'user':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    clean_data = validate_input(data, ['invitation_code'])
    
    if not clean_data:
        return jsonify({'error': 'Invalid input'}), 400
    
    invitation_code = clean_data['invitation_code']
    
    user = db.find_one('users', {'_id': uid})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.get('used_invitation_code'):
        return jsonify({'error': 'Already used invitation code'}), 400
    
    invitation = db.find_one('invitations', {'code': invitation_code})
    if not invitation:
        return jsonify({'error': 'Invalid invitation code'}), 400
    
    if invitation.get('used_by'):
        return jsonify({'error': 'Invitation code already used'}), 400
    
    if invitation['owner_id'] == uid:
        return jsonify({'error': 'Cannot use own invitation code'}), 400
    
    try:
        db.update_one('users', 
            {'_id': uid},
            {
                '$set': {'used_invitation_code': invitation_code},
                '$inc': {'points': 10}
            }
        )
        
        db.update_one('invitations',
            {'code': invitation_code},
            {'$set': {'used_by': uid, 'used_at': datetime.now().isoformat()}}
        )
        
        new_points = user.get('points', 0) + 10
        
        return jsonify({
            'success': True,
            'points_added': 10,
            'total_points': new_points
        }), 200
        
    except Exception:
        return jsonify({'error': 'Failed to use invitation code'}), 500

@app.route('/u/invitation-code', methods=['GET'])
@auth_required
def get_invitation_code(uid, utype):
    if utype != 'user':
        return jsonify({'error': 'Unauthorized'}), 403
    
    cache_key = get_cache_key('invitation_code', uid)
    cached_code = cache_get(cache_key)
    
    if cached_code:
        return jsonify({'invitation_code': cached_code}), 200
    
    user = db.find_one('users', {'_id': uid})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    invitation_code = user.get('invitation_code')
    if invitation_code:
        cache_set(cache_key, invitation_code, 3600)
    
    return jsonify({'invitation_code': invitation_code}), 200

@app.route('/u/points', methods=['GET'])
@auth_required
def get_points(uid, utype):
    if utype != 'user':
        return jsonify({'error': 'Unauthorized'}), 403
    
    cache_key = get_cache_key('points', uid)
    cached_points = cache_get(cache_key)
    
    if cached_points:
        return jsonify({'points': int(cached_points)}), 200
    
    user = db.find_one('users', {'_id': uid})
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    points = user.get('points', 0)
    cache_set(cache_key, str(points), 300)
    
    return jsonify({'points': points}), 200

@app.route('/u/profile', methods=['GET'])
@auth_required
def u_get_profile(uid, utype):
    if utype != 'user':
        return jsonify({'error': 'Unauthorized'}), 403

    cache_key = get_cache_key('profile', uid)
    cached_profile = cache_get(cache_key)

    if cached_profile:
        return Response(cached_profile, status=200, mimetype='application/json')

    user = db.find_one('users', {'_id': uid})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Remove password from response
    user_copy = deepcopy(user)
    if 'password' in user_copy:
        del user_copy['password']
    
    json_user = json.dumps(user_copy, ensure_ascii=False, default=str)
    cache_set(cache_key, json_user, 3600)

    return Response(json_user, status=200, mimetype='application/json')

@app.route('/u/appointments', methods=['GET'])
@auth_required
def u_get_appointments(uid, utype):
    skip = int(request.args.get('skip', 0))
    limit = int(request.args.get('limit', 30))

    cache_key = get_cache_key(f'appointments_{uid}_{skip}_{limit}')
    cached_appointments = cache_get(cache_key)

    if cached_appointments:
        return Response(cached_appointments, mimetype='application/json'), 200

    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

    # Convert today to string for comparison with JSON dates
    today_str = today.isoformat()

    appointments = db.find('tikis', {
        'clientID': uid,
        'date': {'$gte': today_str},
    })

    # Apply skip and limit manually
    appointments = appointments[skip:skip+limit] if limit else appointments[skip:]

    # Sort by date
    appointments.sort(key=lambda x: x.get('date', ''))

    # Remove _id from response
    for appointment in appointments:
        if '_id' in appointment:
            del appointment['_id']

    json_appointments = json.dumps(appointments, ensure_ascii=False, default=str)
    cache_set(cache_key, json_appointments, 300)

    return Response(json_appointments, mimetype='application/json'), 200

@app.route('/u/book', methods=['POST'])
@auth_required
@rate_limit(max_requests=5, window=60)
def u_book(uid, utype):
    if utype != 'user':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    if not data or 'serviceID' not in data or 'date' not in data:
        return jsonify({'error': 'Invalid input'}), 400

    sid = data['serviceID']
    date_str = data['date']

    try:
        book_date = parse_date(date_str).replace(tzinfo=None)  
        book_date = book_date.replace(hour=0, minute=0, second=0, microsecond=0) 
    except Exception:
        return jsonify({'error': 'Invalid date format'}), 400

    if book_date < datetime.now().replace(hour=0, minute=0, second=0, microsecond=0):
        return jsonify({'error': 'Cannot book past dates'}), 400

    month_start = book_date.replace(day=1)
    next_month = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1)

    monthly_bookings = db.count_documents('tikis', {
        'clientID': uid,
        'date': {
            '$gte': month_start.isoformat(),
            '$lt': next_month.isoformat()
        }
    })

    if monthly_bookings >= 20:
        return jsonify({'error': 'Monthly limit exceeded'}), 429

    service = db.find_one('services', {'_id': sid})
    if not service or service.get('status') != 'active':
        return jsonify({'error': 'Service not available'}), 404

    user = db.find_one('users', {'_id': uid})
    if not user or 'name' not in user:
        return jsonify({'error': 'User not found or incomplete profile'}), 404

    tiki_num = get_next_tiki_num(sid, book_date.isoformat())
    if tiki_num is None:
        return jsonify({'error': 'Failed to assign number'}), 500

    tiki_data = {
        'serviceID': sid,
        'serviceAddress': service['address'],
        'serviceName': service['name'],
        'serviceType': service['type'],
        'status': 'waiting',
        'tikiNumber': tiki_num,
        'wilaya': service['wilaya'],
        'date': book_date.isoformat(),
        'clientID': uid,
        'clientName': user['name'],
        'createdAt': datetime.now(timezone.utc).isoformat()
    }

    try:
        db.insert_one('tikis', tiki_data)

        cache_del(get_cache_key('appointments', uid))
        cache_del(get_cache_key('daily_limit', uid, sid, date_str))

        return jsonify({'tikiNumber': tiki_num}), 201

    except Exception as e:
        if 'duplicate key' in str(e):
            return jsonify({'error': 'Already booked today'}), 409
        print("Booking Error:", str(e))
        return jsonify({'error': 'Booking failed'}), 500

@app.route('/service/<service_id>/waiting-count', methods=['GET'])
@auth_required
def get_waiting_count(uid, utype, service_id):
    date_str = request.args.get('date')
    if not date_str:
        return jsonify({'error': 'Missing date parameter'}), 400

    try:
        the_date = parse_date(date_str).replace(tzinfo=None)
        the_date = the_date.replace(hour=0, minute=0, second=0, microsecond=0)

        next_day = the_date + timedelta(days=1)

        count = db.count_documents('tikis', {
            'serviceID': service_id,
            'date': {'$gte': the_date.isoformat(), '$lt': next_day.isoformat()},
            'status': 'waiting'
        })

        return jsonify({
            'serviceId': service_id,
            'date': date_str,
            'waitingCount': count
        }), 200

    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/service/<service_id>/appointments/<date>', methods=['GET'])
@auth_required
def get_service_appointments(uid, utype, service_id, date):
    try:
        datetime.strptime(date, '%Y-%m-%d')
        
        appointments = db.find('tikis', {
            'serviceID': service_id,
            'date': date,
            'status': {'$nin': ['cancelled', 'completed']}
        })

        # Remove _id and keep only needed fields
        filtered_appointments = []
        for appointment in appointments:
            filtered_appointment = {
                'tikiNumber': appointment.get('tikiNumber'),
                'status': appointment.get('status'),
                'clientId': appointment.get('clientID')
            }
            filtered_appointments.append(filtered_appointment)

        # Sort by tikiNumber
        filtered_appointments.sort(key=lambda x: x.get('tikiNumber', 0))

        return jsonify(filtered_appointments), 200
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/services', methods=['GET'])
@auth_required
def get_all_services(uid, utype):
    skip = int(request.args.get('skip', 0))
    limit = int(request.args.get('limit', 100))

    cache_key = get_cache_key(f'all_services_{skip}_{limit}')
    cached_services = cache_get(cache_key)

    if cached_services:
        return Response(cached_services, mimetype='application/json'), 200

    services_list = db.find('services', {
        'status': 'active',
        'payment': True
    })

    # Apply skip and limit
    services_list = services_list[skip:skip+limit] if limit else services_list[skip:]

    # Keep only needed fields
    filtered_services = []
    for service in services_list:
        filtered_service = {
            '_id': service['_id'],
            'name': service.get('name'),
            'type': service.get('type'),
            'wilaya': service.get('wilaya'),
            'address': service.get('address'),
            'phone_number': service.get('phone_number'),
            'price': service.get('price')
        }
        filtered_services.append(filtered_service)

    json_services = json.dumps(filtered_services, ensure_ascii=False, default=str)
    cache_set(cache_key, json_services, 300)

    return Response(json_services, mimetype='application/json'), 200

@app.route('/search', methods=['GET'])
@auth_required
def search_services(uid, utype):
    if utype != 'user':
        return jsonify({'error': 'Unauthorized'}), 403
    
    query = {'status': 'active'}
    cache_params = []
    
    if request.args.get('name'):
        name = html.escape(request.args.get('name').strip())
        query['name'] = {'$regex': name, '$options': 'i'}
        cache_params.append(f"name:{name}")
    
    if request.args.get('wilaya'):
        wilaya = html.escape(request.args.get('wilaya').strip())
        query['wilaya'] = wilaya
        cache_params.append(f"wilaya:{wilaya}")
    
    if request.args.get('type'):
        stype = html.escape(request.args.get('type').strip())
        query['type'] = stype
        cache_params.append(f"type:{stype}")
    
    cache_key = get_cache_key('search', *cache_params)
    cached_results = cache_get(cache_key)
    
    if cached_results:
        return jsonify(json.loads(cached_results)), 200
    
    services_list = db.find('services', query)
    
    # Limit to 20 results
    services_list = services_list[:20]
    
    # Keep only needed fields
    filtered_services = []
    for service in services_list:
        filtered_service = {
            '_id': service['_id'],
            'name': service.get('name'),
            'type': service.get('type'),
            'wilaya': service.get('wilaya'),
            'address': service.get('address'),
            'phone_number': service.get('phone_number')
        }
        filtered_services.append(filtered_service)
    
    cache_set(cache_key, json.dumps(filtered_services, ensure_ascii=False, default=str), 600)
    return jsonify(filtered_services), 200

@app.route('/s/reg', methods=['POST'])
@rate_limit(max_requests=3, window=300)
def s_reg():
    data = request.get_json()
    fields = ['email', 'password', 'name', 'type', 'wilaya', 'address', 'age', 'gender', 'phone_number']
    clean_data = validate_input(data, fields)
    
    if not clean_data or len(clean_data) < 9:
        return jsonify({'error': 'Invalid input'}), 400
    
    try:
        service_data = {
            'email': clean_data['email'],
            'password': hash_pwd(clean_data['password']).decode('utf-8'),
            'name': clean_data['name'],
            'type': clean_data['type'],
            'wilaya': clean_data['wilaya'],
            'address': clean_data['address'],
            'age': clean_data['age'],
            'gender': clean_data['gender'],
            'phone_number': clean_data['phone_number'],
            'createdAt': datetime.now().isoformat(),
            'status': 'active'
        }
        
        result = db.insert_one('services', service_data)
        token = gen_token(result.inserted_id, 'service')
        
        return jsonify({'token': token, 'sid': str(result.inserted_id)}), 201
    except Exception as e:
        if 'duplicate key' in str(e):
            return jsonify({'error': 'Email already exists'}), 409
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/s/login', methods=['POST'])
@rate_limit(max_requests=10, window=300)
def s_login():
    data = request.get_json()
    clean_data = validate_input(data, ['email', 'password'])
    
    if not clean_data:
        return jsonify({'error': 'Invalid input'}), 400
    
    service = db.find_one('services', {'email': clean_data['email']})
    
    if service and service.get('status') == 'active' and check_pwd(clean_data['password'], service['password'].encode('utf-8')):
        token = gen_token(service['_id'], 'service')
        return jsonify({'token': token, 'sid': str(service['_id'])}), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/s/appointments/<date>', methods=['GET'])
@auth_required
def s_get_appointments(uid, utype, date):
    if utype != 'service':
        return jsonify({'error': 'Unauthorized'}), 403
    
    cache_key = get_cache_key('service_appointments', uid, date)
    cached_appointments = cache_get(cache_key)
    
    if cached_appointments:
        return jsonify(json.loads(cached_appointments)), 200
    
    try:
        datetime.strptime(date, '%Y-%m-%d')
    except ValueError:
        return jsonify({'error': 'Invalid date'}), 400
    
    appointments = db.find('tikis', {
        'serviceID': uid,
        'date': date
    })
    
    # Keep only needed fields and sort by tikiNumber
    filtered_appointments = []
    for appointment in appointments:
        filtered_appointment = {
            'tikiNumber': appointment.get('tikiNumber'),
            'clientName': appointment.get('clientName'),
            'clientPhone': appointment.get('clientPhone'),
            'status': appointment.get('status'),
            'createdAt': appointment.get('createdAt')
        }
        filtered_appointments.append(filtered_appointment)
    
    filtered_appointments.sort(key=lambda x: x.get('tikiNumber', 0))
    
    cache_set(cache_key, json.dumps(filtered_appointments, ensure_ascii=False, default=str), 300)
    return jsonify(filtered_appointments), 200

@app.route('/s/status', methods=['PUT'])
@auth_required
@rate_limit(max_requests=100, window=60)
def s_update_status(uid, utype):
    if utype != 'service':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    clean_data = validate_input(data, ['date', 'tikiNumber', 'status'])
    
    if not clean_data:
        return jsonify({'error': 'Invalid input'}), 400
    
    if clean_data['status'] not in ['pending', 'confirmed', 'cancelled', 'completed']:
        return jsonify({'error': 'Invalid status'}), 400
    
    result = db.update_one('tikis',
        {
            'serviceID': uid,
            'date': clean_data['date'],
            'tikiNumber': clean_data['tikiNumber']
        },
        {'$set': {'status': clean_data['status'], 'updatedAt': datetime.now().isoformat()}}
    )
    
    if result.matched_count == 0:
        return jsonify({'error': 'Appointment not found'}), 404
    
    cache_del(get_cache_key('service_appointments', uid, clean_data['date']))
    
    return jsonify({'success': True}), 200

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'error': 'Rate limit exceeded'}), 429

if __name__ == '__main__':
    app.run(debug=False, threaded=True, host='0.0.0.0', port=5000)
