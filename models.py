from datetime import datetime
from pymongo import ASCENDING, DESCENDING
from utils import get_mongo_db, check_mongodb_connection
from extensions import mongo_client
from logging import getLogger
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
import uuid

logger = getLogger('ficore_app')

# Sample courses data
SAMPLE_COURSES = [
    {
        'id': 'budgeting_learning_101',
        'title_key': 'learning_hub_course_budgeting101_title',
        'title_en': 'Budgeting Learning 101',
        'title_ha': 'Tsarin Kudi 101',
        'description_en': 'Learn the basics of budgeting.',
        'description_ha': 'Koyon asalin tsarin kudi.',
        'is_premium': False
    },
    {
        'id': 'financial_quiz',
        'title_key': 'learning_hub_course_financial_quiz_title',
        'title_en': 'Financial Quiz',
        'title_ha': 'Jarabawar Kudi',
        'description_en': 'Test your financial knowledge.',
        'description_ha': 'Gwada ilimin ku na kudi.',
        'is_premium': False
    },
    {
        'id': 'savings_basics',
        'title_key': 'learning_hub_course_savings_basics_title',
        'title_en': 'Savings Basics',
        'title_ha': 'Asalin Tattara Kudi',
        'description_en': 'Understand how to save effectively.',
        'description_ha': 'Fahimci yadda ake tattara kudi yadda ya kamata.',
        'is_premium': False
    }
]

def initialize_database(app):
    max_retries = 3
    for attempt in range(max_retries):
        try:
            if check_mongodb_connection(mongo_client, app):
                logger.info(f"Attempt {attempt + 1}/{max_retries} - MongoDB connection established")
                break
            else:
                logger.warning(f"Attempt {attempt + 1}/{max_retries} - MongoDB connection not ready")
                if attempt == max_retries - 1:
                    logger.error("Max retries reached: MongoDB connection not established")
                    raise RuntimeError("MongoDB connection failed after max retries")
        except Exception as e:
            logger.error(f"Failed to initialize database (attempt {attempt + 1}/{max_retries}): {e}", exc_info=True)
            if attempt == max_retries - 1:
                raise
    try:
        db_instance = get_mongo_db()
        try:
            db_instance.command('ping')
        except Exception as e:
            logger.error(f"MongoDB client is closed before database operations: {str(e)}")
            raise RuntimeError("MongoDB client is closed")
        logger.info(f"MongoDB database: {db_instance.name}")
        collections = db_instance.list_collection_names()
        collection_schemas = {
            'users': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['_id', 'email', 'password', 'role'],
                        'properties': {
                            '_id': {'bsonType': 'string'},
                            'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                            'password': {'bsonType': 'string'},
                            'role': {'enum': ['personal', 'trader', 'agent', 'admin']},
                            'coin_balance': {'bsonType': 'int', 'minimum': 0},
                            'language': {'enum': ['en', 'ha']},
                            'created_at': {'bsonType': 'date'},
                            'display_name': {'bsonType': ['string', 'null']},
                            'is_admin': {'bsonType': 'bool'},
                            'setup_complete': {'bsonType': 'bool'},
                            'reset_token': {'bsonType': ['string', 'null']},
                            'reset_token_expiry': {'bsonType': ['date', 'null']},
                            'otp': {'bsonType': ['string', 'null']},
                            'otp_expiry': {'bsonType': ['date', 'null']},
                            'business_details': {
                                'bsonType': ['object', 'null'],
                                'properties': {
                                    'name': {'bsonType': 'string'},
                                    'address': {'bsonType': 'string'},
                                    'industry': {'bsonType': 'string'},
                                    'products_services': {'bsonType': 'string'},
                                    'phone_number': {'bsonType': 'string'}
                                }
                            },
                            'personal_details': {
                                'bsonType': ['object', 'null'],
                                'properties': {
                                    'first_name': {'bsonType': 'string'},
                                    'last_name': {'bsonType': 'string'},
                                    'phone_number': {'bsonType': 'string'},
                                    'address': {'bsonType': 'string'}
                                }
                            },
                            'agent_details': {
                                'bsonType': ['object', 'null'],
                                'properties': {
                                    'agent_name': {'bsonType': 'string'},
                                    'agent_id': {'bsonType': 'string'},
                                    'area': {'bsonType': 'string'},
                                    'role': {'bsonType': 'string'},
                                    'email': {'bsonType': 'string'},
                                    'phone': {'bsonType': 'string'}
                                }
                            }
                        }
                    }
                },
                'indexes': [
                    {'key': [('email', ASCENDING)], 'unique': True},
                    {'key': [('reset_token', ASCENDING)], 'sparse': True},
                    {'key': [('role', ASCENDING)]}
                ]
            },
            'records': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'name', 'amount_owed', 'type', 'created_at'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'name': {'bsonType': 'string'},
                            'amount_owed': {'bsonType': 'double', 'minimum': 0},
                            'type': {'enum': ['debtor', 'creditor']},
                            'created_at': {'bsonType': 'date'},
                            'contact': {'bsonType': ['string', 'null']},
                            'description': {'bsonType': ['string', 'null']},
                            'reminder_count': {'bsonType': ['int', 'null'], 'minimum': 0}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING), ('type', ASCENDING)]},
                    {'key': [('created_at', DESCENDING)]}
                ]
            },
            'cashflows': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'amount', 'party_name', 'type', 'created_at'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'amount': {'bsonType': 'double', 'minimum': 0},
                            'party_name': {'bsonType': 'string'},
                            'type': {'enum': ['payment', 'receipt']},
                            'created_at': {'bsonType': 'date'},
                            'method': {'enum': ['card', 'bank', 'cash', None]},
                            'category': {'bsonType': ['string', 'null']},
                            'file_id': {'bsonType': ['objectId', 'null']},
                            'filename': {'bsonType': ['string', 'null']}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING), ('type', ASCENDING)]},
                    {'key': [('created_at', DESCENDING)]}
                ]
            },
            'inventory': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'item_name', 'qty', 'created_at'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'item_name': {'bsonType': 'string'},
                            'qty': {'bsonType': 'int', 'minimum': 0},
                            'created_at': {'bsonType': 'date'},
                            'unit': {'bsonType': ['string', 'null']},
                            'buying_price': {'bsonType': ['double', 'null'], 'minimum': 0},
                            'selling_price': {'bsonType': ['double', 'null'], 'minimum': 0},
                            'threshold': {'bsonType': ['int', 'null'], 'minimum': 0},
                            'updated_at': {'bsonType': ['date', 'null']}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('created_at', DESCENDING)]}
                ]
            },
            'coin_transactions': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'amount', 'type', 'date'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'amount': {'bsonType': 'int'},
                            'type': {'enum': ['purchase', 'spend', 'credit', 'admin_credit']},
                            'date': {'bsonType': 'date'},
                            'ref': {'bsonType': ['string', 'null']},
                            'facilitated_by_agent': {'bsonType': ['string', 'null']},
                            'payment_method': {'bsonType': ['string', 'null']},
                            'cash_amount': {'bsonType': ['double', 'null']},
                            'notes': {'bsonType': ['string', 'null']}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('date', DESCENDING)]},
                    {'key': [('facilitated_by_agent', ASCENDING)], 'sparse': True}
                ]
            },
            'agent_activities': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['agent_id', 'activity_type', 'timestamp'],
                        'properties': {
                            'agent_id': {'bsonType': 'string'},
                            'activity_type': {'enum': ['trader_registration', 'token_facilitation', 'report_generation', 'trader_assistance']},
                            'trader_id': {'bsonType': ['string', 'null']},
                            'details': {'bsonType': ['object', 'null']},
                            'timestamp': {'bsonType': 'date'}
                        }
                    }
                },
                'indexes': [
                    {'key': [('agent_id', ASCENDING)]},
                    {'key': [('timestamp', DESCENDING)]},
                    {'key': [('trader_id', ASCENDING)], 'sparse': True}
                ]
            },
            'audit_logs': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['admin_id', 'action', 'details', 'timestamp'],
                        'properties': {
                            'admin_id': {'bsonType': 'string'},
                            'action': {'bsonType': 'string'},
                            'details': {'bsonType': ['object', 'null']},
                            'timestamp': {'bsonType': 'date'}
                        }
                    }
                },
                'indexes': [
                    {'key': [('timestamp', DESCENDING)]}
                ]
            },
            'feedback': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'tool_name', 'rating', 'timestamp'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'tool_name': {'bsonType': 'string'},
                            'rating': {'bsonType': 'int', 'minimum': 1, 'maximum': 5},
                            'comment': {'bsonType': ['string', 'null']},
                            'timestamp': {'bsonType': 'date'}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING)], 'sparse': True},
                    {'key': [('timestamp', DESCENDING)]}
                ]
            },
            'reminder_logs': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'debt_id', 'recipient', 'message', 'type', 'sent_at', 'notification_id', 'read_status'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'debt_id': {'bsonType': 'string'},
                            'recipient': {'bsonType': 'string'},
                            'message': {'bsonType': 'string'},
                            'type': {'enum': ['sms', 'whatsapp']},
                            'sent_at': {'bsonType': 'date'},
                            'api_response': {'bsonType': ['object', 'null']},
                            'notification_id': {'bsonType': 'string'},
                            'read_status': {'bsonType': 'bool'}
                        }
                    }
                },
                'indexes': [
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('debt_id', ASCENDING)]},
                    {'key': [('sent_at', DESCENDING)]},
                    {'key': [('notification_id', ASCENDING)], 'unique': True}
                ]
            },
            'sessions': {
                'validator': {},
                'indexes': [
                    {'key': [('expiration', ASCENDING)], 'expireAfterSeconds': 0, 'name': 'expiration_1'}
                ]
            },
            'courses': {
                'indexes': [
                    {'key': [('id', ASCENDING)], 'unique': True}
                ]
            },
            'content_metadata': {
                'indexes': [
                    {'key': [('course_id', ASCENDING), ('lesson_id', ASCENDING)], 'unique': True}
                ]
            },
            'financial_health': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'budgets': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'bills': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('user_email', ASCENDING)]},
                    {'key': [('status', ASCENDING)]},
                    {'key': [('due_date', ASCENDING)]}
                ]
            },
            'net_worth': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'emergency_funds': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'learning_progress': {
                'indexes': [
                    {'key': [('user_id', ASCENDING), ('course_id', ASCENDING)], 'unique': True},
                    {'key': [('session_id', ASCENDING), ('course_id', ASCENDING)], 'unique': True},
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'quiz_results': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]}
                ]
            },
            'tool_usage': {
                'indexes': [
                    {'key': [('session_id', ASCENDING)]},
                    {'key': [('user_id', ASCENDING)]},
                    {'key': [('tool_name', ASCENDING)]}
                ]
            },
            'reset_tokens': {
                'indexes': [
                    {'key': [('token', ASCENDING)], 'unique': True}
                ]
            }
        }
        for collection_name, config in collection_schemas.items():
            if collection_name not in collections:
                db_instance.create_collection(collection_name, validator=config.get('validator', {}))
                logger.info(f"Created collection: {collection_name}")
            existing_indexes = db_instance[collection_name].index_information()
            for index in config.get('indexes', []):
                keys = index['key']
                options = {k: v for k, v in index.items() if k != 'key'}
                index_key_tuple = tuple(keys)
                index_name = options.get('name', '')
                index_exists = False
                for existing_index_name, existing_index_info in existing_indexes.items():
                    if tuple(existing_index_info['key']) == index_key_tuple:
                        existing_options = {k: v for k, v in existing_index_info.items() if k not in ['key', 'v', 'ns']}
                        if existing_options == options:
                            logger.info(f"Index already exists on {collection_name}: {keys} with options {options}")
                            index_exists = True
                        else:
                            logger.warning(f"Index conflict on {collection_name}: {keys}. Existing options: {existing_options}, Requested: {options}")
                        break
                if not index_exists:
                    if collection_name == 'sessions' and index_name == 'expiration_1':
                        if 'expiration_1' not in existing_indexes:
                            db_instance[collection_name].create_index(keys, **options)
                            logger.info(f"Created index on {collection_name}: {keys} with options {options}")
                    else:
                        db_instance[collection_name].create_index(keys, **options)
                        logger.info(f"Created index on {collection_name}: {keys} with options {options}")
        courses_collection = db_instance.courses
        if courses_collection.count_documents({}) == 0:
            for course in SAMPLE_COURSES:
                courses_collection.insert_one(course)
            logger.info("Initialized courses in MongoDB")
        app.config['COURSES'] = list(courses_collection.find({}, {'_id': 0}))
    except Exception as e:
        logger.error(f"Failed to initialize database indexes/courses: {str(e)}", exc_info=True)
        raise

# User class for Flask-Login - aligned with users blueprint expectations
class User:
    def __init__(self, id, email, display_name=None, role='personal', username=None, is_admin=False, setup_complete=False, coin_balance=0, language='en', dark_mode=False):
        self.id = id
        self.email = email
        self.username = username or display_name or email.split('@')[0]
        self.role = role
        self.display_name = display_name or self.username
        self.is_admin = is_admin
        self.setup_complete = setup_complete
        self.coin_balance = coin_balance
        self.language = language
        self.dark_mode = dark_mode

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def get(self, key, default=None):
        """Get attribute value with default fallback - matches users blueprint usage"""
        return getattr(self, key, default)

# User management functions - aligned with users blueprint
def create_user(db, user_data):
    """Create a new user in the database - matches users blueprint expectations"""
    try:
        # Use username as _id to match users blueprint pattern
        user_id = user_data.get('username', user_data['email'].split('@')[0]).lower()
        
        user_doc = {
            '_id': user_id,
            'email': user_data['email'].lower(),
            'password': user_data['password_hash'],
            'role': user_data.get('role', 'personal'),
            'display_name': user_data.get('display_name', user_id),
            'is_admin': user_data.get('is_admin', False),
            'setup_complete': user_data.get('setup_complete', False),
            'coin_balance': user_data.get('coin_balance', 10),
            'language': user_data.get('lang', 'en'),
            'dark_mode': user_data.get('dark_mode', False),
            'created_at': user_data.get('created_at', datetime.utcnow()),
            'business_details': user_data.get('business_details'),
            'personal_details': user_data.get('personal_details'),
            'agent_details': user_data.get('agent_details')
        }
        
        db.users.insert_one(user_doc)
        logger.info(f"Created user with ID: {user_id}")
        
        return User(
            id=user_id,
            email=user_doc['email'],
            username=user_id,
            role=user_doc['role'],
            display_name=user_doc['display_name'],
            is_admin=user_doc['is_admin'],
            setup_complete=user_doc['setup_complete'],
            coin_balance=user_doc['coin_balance'],
            language=user_doc['language'],
            dark_mode=user_doc['dark_mode']
        )
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        raise

def get_user_by_email(db, email):
    """Get user by email address - matches users blueprint expectations"""
    try:
        user_doc = db.users.find_one({'email': email.lower()})
        if user_doc:
            return User(
                id=user_doc['_id'],
                email=user_doc['email'],
                username=user_doc['_id'],  # username is the _id in users blueprint
                role=user_doc.get('role', 'personal'),
                display_name=user_doc.get('display_name'),
                is_admin=user_doc.get('is_admin', False),
                setup_complete=user_doc.get('setup_complete', False),
                coin_balance=user_doc.get('coin_balance', 0),
                language=user_doc.get('language', 'en'),
                dark_mode=user_doc.get('dark_mode', False)
            )
        return None
    except Exception as e:
        logger.error(f"Error getting user by email {email}: {str(e)}")
        return None

def get_user(db, user_id):
    """Get user by ID - matches users blueprint expectations"""
    try:
        user_doc = db.users.find_one({'_id': user_id})
        if user_doc:
            return User(
                id=user_doc['_id'],
                email=user_doc['email'],
                username=user_doc['_id'],  # username is the _id in users blueprint
                role=user_doc.get('role', 'personal'),
                display_name=user_doc.get('display_name'),
                is_admin=user_doc.get('is_admin', False),
                setup_complete=user_doc.get('setup_complete', False),
                coin_balance=user_doc.get('coin_balance', 0),
                language=user_doc.get('language', 'en'),
                dark_mode=user_doc.get('dark_mode', False)
            )
        return None
    except Exception as e:
        logger.error(f"Error getting user by ID {user_id}: {str(e)}")
        return None

# Personal finance data retrieval functions
def get_financial_health(db, filter_kwargs):
    """Get financial health records"""
    try:
        collection_name = 'financial_health_scores'
        if collection_name in db.list_collection_names():
            return list(db[collection_name].find(filter_kwargs).sort('created_at', -1))
        return []
    except Exception as e:
        logger.error(f"Error getting financial health: {str(e)}")
        return []

def get_budgets(db, filter_kwargs):
    """Get budget records"""
    try:
        return list(db.budgets.find(filter_kwargs).sort('created_at', -1))
    except Exception as e:
        logger.error(f"Error getting budgets: {str(e)}")
        return []

def get_bills(db, filter_kwargs):
    """Get bill records"""
    try:
        return list(db.bills.find(filter_kwargs).sort('due_date', 1))
    except Exception as e:
        logger.error(f"Error getting bills: {str(e)}")
        return []

def get_net_worth(db, filter_kwargs):
    """Get net worth records"""
    try:
        collection_name = 'net_worth_data'
        if collection_name in db.list_collection_names():
            return list(db[collection_name].find(filter_kwargs).sort('created_at', -1))
        return []
    except Exception as e:
        logger.error(f"Error getting net worth: {str(e)}")
        return []

def get_emergency_funds(db, filter_kwargs):
    """Get emergency fund records"""
    try:
        return list(db.emergency_funds.find(filter_kwargs).sort('created_at', -1))
    except Exception as e:
        logger.error(f"Error getting emergency funds: {str(e)}")
        return []

def get_learning_progress(db, filter_kwargs):
    """Get learning progress records"""
    try:
        return list(db.learning_materials.find(filter_kwargs))
    except Exception as e:
        logger.error(f"Error getting learning progress: {str(e)}")
        return []

def get_quiz_results(db, filter_kwargs):
    """Get quiz result records"""
    try:
        return list(db.quiz_responses.find(filter_kwargs).sort('created_at', -1))
    except Exception as e:
        logger.error(f"Error getting quiz results: {str(e)}")
        return []

# Data conversion functions for templates
def to_dict_financial_health(record):
    """Convert financial health record to dict"""
    if not record:
        return {'score': None, 'status': None}
    return {
        'score': record.get('score'),
        'status': record.get('status'),
        'debt_to_income': record.get('debt_to_income'),
        'savings_rate': record.get('savings_rate'),
        'interest_burden': record.get('interest_burden'),
        'badges': record.get('badges', []),
        'created_at': record.get('created_at')
    }

def to_dict_budget(record):
    """Convert budget record to dict"""
    if not record:
        return {'surplus_deficit': None, 'savings_goal': None}
    return {
        'income': record.get('income', 0),
        'fixed_expenses': record.get('fixed_expenses', 0),
        'variable_expenses': record.get('variable_expenses', 0),
        'savings_goal': record.get('savings_goal', 0),
        'surplus_deficit': record.get('surplus_deficit', 0),
        'housing': record.get('housing', 0),
        'food': record.get('food', 0),
        'transport': record.get('transport', 0),
        'dependents': record.get('dependents', 0),
        'miscellaneous': record.get('miscellaneous', 0),
        'others': record.get('others', 0),
        'created_at': record.get('created_at')
    }

def to_dict_bill(record):
    """Convert bill record to dict"""
    if not record:
        return {'amount': None, 'status': None}
    return {
        'id': str(record.get('_id', '')),
        'bill_name': record.get('bill_name', ''),
        'amount': record.get('amount', 0),
        'due_date': record.get('due_date', ''),
        'frequency': record.get('frequency', ''),
        'category': record.get('category', ''),
        'status': record.get('status', ''),
        'send_email': record.get('send_email', False),
        'reminder_days': record.get('reminder_days'),
        'user_email': record.get('user_email', ''),
        'first_name': record.get('first_name', '')
    }

def to_dict_net_worth(record):
    """Convert net worth record to dict"""
    if not record:
        return {'net_worth': None, 'total_assets': None}
    return {
        'cash_savings': record.get('cash_savings', 0),
        'investments': record.get('investments', 0),
        'property': record.get('property', 0),
        'loans': record.get('loans', 0),
        'total_assets': record.get('total_assets', 0),
        'total_liabilities': record.get('total_liabilities', 0),
        'net_worth': record.get('net_worth', 0),
        'badges': record.get('badges', []),
        'created_at': record.get('created_at')
    }

def to_dict_emergency_fund(record):
    """Convert emergency fund record to dict"""
    if not record:
        return {'target_amount': None, 'savings_gap': None}
    return {
        'monthly_expenses': record.get('monthly_expenses', 0),
        'monthly_income': record.get('monthly_income', 0),
        'current_savings': record.get('current_savings', 0),
        'risk_tolerance_level': record.get('risk_tolerance_level', ''),
        'dependents': record.get('dependents', 0),
        'timeline': record.get('timeline', 0),
        'recommended_months': record.get('recommended_months', 0),
        'target_amount': record.get('target_amount', 0),
        'savings_gap': record.get('savings_gap', 0),
        'monthly_savings': record.get('monthly_savings', 0),
        'percent_of_income': record.get('percent_of_income'),
        'badges': record.get('badges', []),
        'created_at': record.get('created_at')
    }

def to_dict_learning_progress(record):
    """Convert learning progress record to dict"""
    if not record:
        return {'lessons_completed': [], 'quiz_scores': {}}
    return {
        'course_id': record.get('course_id', ''),
        'lessons_completed': record.get('lessons_completed', []),
        'quiz_scores': record.get('quiz_scores', {}),
        'current_lesson': record.get('current_lesson')
    }

def to_dict_quiz_result(record):
    """Convert quiz result record to dict"""
    if not record:
        return {'personality': None, 'score': None}
    return {
        'personality': record.get('personality', ''),
        'score': record.get('score', 0),
        'badges': record.get('badges', []),
        'insights': record.get('insights', []),
        'tips': record.get('tips', []),
        'created_at': record.get('created_at')
    }

# Utility functions
def create_feedback(db, feedback_data):
    """Create feedback record"""
    try:
        db.feedback.insert_one(feedback_data)
        logger.info(f"Created feedback record for tool: {feedback_data.get('tool_name')}")
    except Exception as e:
        logger.error(f"Error creating feedback: {str(e)}")
        raise

def log_tool_usage(mongo, tool_name, user_id=None, session_id=None, action=None):
    """Log tool usage for analytics"""
    try:
        usage_data = {
            'tool_name': tool_name,
            'user_id': user_id,
            'session_id': session_id,
            'action': action,
            'timestamp': datetime.utcnow()
        }
        
        # Handle both mongo db object and mongo client
        if hasattr(mongo, 'db'):
            mongo.db.tool_usage.insert_one(usage_data)
        else:
            mongo.tool_usage.insert_one(usage_data)
        
        logger.info(f"Logged tool usage: {tool_name} - {action}")
    except Exception as e:
        logger.error(f"Error logging tool usage: {str(e)}")
        # Don't raise exception for logging failures
