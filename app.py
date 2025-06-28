import os
import sys
import logging
import uuid
from datetime import datetime, date, timedelta
from flask import (
    Flask, jsonify, request, render_template, redirect, url_for, flash,
    make_response, has_request_context, g, send_from_directory, session, Response, current_app
)
from flask_cors import CORS
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv
import atexit
from functools import wraps
from mailersend_email import init_email_config
from scheduler_setup import init_scheduler
from models import create_user, get_user_by_email, get_user, get_financial_health, get_budgets, get_bills, get_net_worth, get_emergency_funds, get_learning_progress, get_quiz_results, to_dict_financial_health, to_dict_budget, to_dict_bill, to_dict_net_worth, to_dict_emergency_fund, to_dict_learning_progress, to_dict_quiz_result, initialize_database
from utils import trans_function, is_valid_email, get_mongo_db, close_mongo_db, get_limiter, get_mail, requires_role, check_coin_balance
from session_utils import create_anonymous_session
from translations.core import trans
from extensions import mongo_client, login_manager, flask_session, csrf, babel, compress
from flask_login import login_required, current_user

# Load environment variables
load_dotenv()

# Set up logging
root_logger = logging.getLogger('ficore_app')
root_logger.setLevel(logging.INFO)

class SessionFormatter(logging.Formatter):
    def format(self, record):
        record.session_id = getattr(record, 'session_id', 'no-session-id')
        return super().format(record)

formatter = SessionFormatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s [session: %(session_id)s]')

class SessionAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        kwargs['extra'] = kwargs.get('extra', {})
        session_id = 'no-session-id'
        try:
            if has_request_context():
                session_id = session.get('sid', 'no-session-id')
            else:
                session_id = 'no-request-context'
        except Exception as e:
            session_id = 'session-error'
            kwargs['extra']['session_error'] = str(e)
        kwargs['extra']['session_id'] = session_id
        return msg, kwargs

logger = SessionAdapter(root_logger, {})

# Decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('users_bp.login'))
        if current_user.role != 'admin':
            flash(trans('no_permission', default='You do not have permission to access this page.'), 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def custom_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated or session.get('is_anonymous', False):
            return f(*args, **kwargs)
        return redirect(url_for('users_bp.login', next=request.url))
    return decorated_function

def ensure_session_id(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if 'sid' not in session:
                if not current_user.is_authenticated:
                    create_anonymous_session()
                else:
                    session['sid'] = session.sid
                    session['is_anonymous'] = False
                    logger.info(f"New session ID generated for authenticated user: {session['sid']}")
        except Exception as e:
            logger.error(f"Session operation failed: {str(e)}")
        return f(*args, **kwargs)
    return decorated_function

def setup_logging(app):
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.INFO)
    handler.setFormatter(formatter)
    root_logger.handlers = []
    root_logger.addHandler(handler)
    
    flask_logger = logging.getLogger('flask')
    werkzeug_logger = logging.getLogger('werkzeug')
    flask_logger.handlers = []
    werkzeug_logger.handlers = []
    flask_logger.addHandler(handler)
    werkzeug_logger.addHandler(handler)
    flask_logger.setLevel(logging.INFO)
    werkzeug_logger.setLevel(logging.INFO)
    
    logger.info("Logging setup complete with StreamHandler for ficore_app, flask, and werkzeug")

def check_mongodb_connection(mongo_client, app):
    try:
        if mongo_client is None:
            logger.error("MongoDB client is None")
            return False
        try:
            mongo_client.admin.command('ping')
            logger.info("MongoDB connection verified with ping")
            return True
        except Exception as e:
            logger.error(f"MongoDB client is closed: {str(e)}")
            try:
                from pymongo import MongoClient
                import certifi
                new_client = MongoClient(
                    app.config['MONGO_URI'],
                    connect=False,
                    tlsCAFile=certifi.where(),
                    maxPoolSize=20,
                    socketTimeoutMS=60000,
                    connectTimeoutMS=30000,
                    serverSelectionTimeoutMS=30000,
                    retryWrites=True
                )
                new_client.admin.command('ping')
                logger.info("New MongoDB client reinitialized successfully")
                app.config['MONGO_CLIENT'] = new_client
                app.config['SESSION_MONGODB'] = new_client
                return True
            except Exception as reinit_e:
                logger.error(f"Failed to reinitialize MongoDB client: {str(reinit_e)}")
                return False
    except Exception as e:
        logger.error(f"MongoDB connection error: {str(e)}", exc_info=True)
        return False

def setup_session(app):
    try:
        if not check_mongodb_connection(mongo_client, app):
            logger.error("MongoDB client is not open, attempting to reinitialize")
            from pymongo import MongoClient
            import certifi
            mongo_client_new = MongoClient(
                app.config['MONGO_URI'],
                connect=False,
                tlsCAFile=certifi.where(),
                maxPoolSize=20,
                socketTimeoutMS=60000,
                connectTimeoutMS=30000,
                serverSelectionTimeoutMS=30000,
                retryWrites=True
            )
            if not check_mongodb_connection(mongo_client_new, app):
                logger.error("MongoDB client could not be reinitialized, falling back to filesystem session")
                app.config['SESSION_TYPE'] = 'filesystem'
                flask_session.init_app(app)
                logger.info("Session configured with filesystem fallback")
                return
            app.config['MONGO_CLIENT'] = mongo_client_new
        app.config['SESSION_TYPE'] = 'mongodb'
        app.config['SESSION_MONGODB'] = mongo_client
        app.config['SESSION_MONGODB_DB'] = 'ficodb'
        app.config['SESSION_MONGODB_COLLECT'] = 'sessions'
        app.config['SESSION_PERMANENT'] = True
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
        app.config['SESSION_USE_SIGNER'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV', 'development') == 'production'
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_NAME'] = 'ficore_session'
        flask_session.init_app(app)
        logger.info(f"Session configured: type={app.config['SESSION_TYPE']}, db={app.config['SESSION_MONGODB_DB']}, collection={app.config['SESSION_MONGODB_COLLECT']}")
    except Exception as e:
        logger.error(f"Failed to configure session with MongoDB: {str(e)}", exc_info=True)
        app.config['SESSION_TYPE'] = 'filesystem'
        flask_session.init_app(app)
        logger.info("Session configured with filesystem fallback due to MongoDB error")

class User:
    def __init__(self, id, email, display_name=None, role='personal'):
        self.id = id
        self.email = email
        self.display_name = display_name or id
        self.role = role

    def get(self, key, default=None):
        user = get_mongo_db().users.find_one({'_id': self.id})
        return user.get(key, default) if user else default

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

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    CORS(app)
    
    # Load configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    if not app.config['SECRET_KEY']:
        logger.error("SECRET_KEY environment variable is not set")
        raise ValueError("SECRET_KEY must be set in environment variables")
    
    app.config['MONGO_URI'] = os.getenv('MONGO_URI')
    if not app.config['MONGO_URI']:
        logger.error("MONGO_URI environment variable is not set")
        raise ValueError("MONGO_URI must be set in environment variables")
    
    app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
    app.config['SMTP_SERVER'] = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    app.config['SMTP_PORT'] = int(os.environ.get('SMTP_PORT', 587))
    app.config['SMTP_USERNAME'] = os.environ.get('SMTP_USERNAME')
    app.config['SMTP_PASSWORD'] = os.environ.get('SMTP_PASSWORD')
    app.config['BASE_URL'] = os.environ.get('BASE_URL', 'http://localhost:5000')
    
    if not app.config['GOOGLE_CLIENT_ID'] or not app.config['GOOGLE_CLIENT_SECRET']:
        logger.warning("Google OAuth2 credentials not set")
    if not app.config['SMTP_USERNAME'] or not app.config['SMTP_PASSWORD']:
        logger.warning("SMTP credentials not set")
    
    # Initialize extensions
    setup_logging(app)
    compress.init_app(app)
    csrf.init_app(app)
    mail = get_mail(app)
    limiter = get_limiter(app)
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    babel.init_app(app)
    setup_session(app)
    
    # Flask-Babel locale selector
    def get_locale():
        return session.get('lang', request.accept_languages.best_match(['en', 'ha'], default='en'))
    babel.locale_selector = get_locale
    
    # Configure Flask-Login
    login_manager.init_app(app)
    login_manager.login_view = 'users_bp.login'
    login_manager.login_message = trans('login_required', default='Please log in to access this page.')
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        try:
            user = get_user(get_mongo_db(), user_id)
            if user is None:
                logger.warning(f"No user found for ID: {user_id}")
            else:
                logger.info(f"User loaded: {user.username if hasattr(user, 'username') else user_id}")
            return user
        except Exception as e:
            logger.error(f"Error loading user {user_id}: {str(e)}", exc_info=True)
            return None
    
    # Initialize scheduler
    try:
        with app.app_context():
            scheduler = init_scheduler(app, get_mongo_db())
            app.config['SCHEDULER'] = scheduler
            logger.info("Scheduler initialized successfully")
            def shutdown_scheduler():
                try:
                    if scheduler and scheduler.running:
                        scheduler.shutdown(wait=True)
                        logger.info("Scheduler shutdown successfully")
                except Exception as e:
                    logger.error(f"Error shutting down scheduler: {str(e)}", exc_info=True)
            atexit.register(shutdown_scheduler)
    except Exception as e:
        logger.error(f"Failed to initialize scheduler: {str(e)}", exc_info=True)
    
    # Initialize database
    with app.app_context():
        initialize_database(app)
        admin_email = os.environ.get('ADMIN_EMAIL', 'ficorerecords@gmail.com')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin123!')
        admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
        admin_user = get_user_by_email(get_mongo_db(), admin_email)
        if not admin_user:
            user_data = {
                'username': admin_username.lower(),
                'email': admin_email.lower(),
                'password_hash': generate_password_hash(admin_password),
                'is_admin': True,
                'role': 'admin',
                'created_at': datetime.utcnow(),
                'lang': 'en',
                'setup_complete': True,
                'display_name': admin_username
            }
            admin_user = create_user(get_mongo_db(), user_data)
            logger.info(f"Admin user created with email: {admin_email}")
        else:
            logger.info(f"Admin user already exists with email: {admin_email}")
    
    # Register blueprints - Import all existing blueprints
    try:
        from users.routes import users_bp
        app.register_blueprint(users_bp, url_prefix='/users')
        logger.info("Registered users blueprint")
    except ImportError as e:
        logger.warning(f"Could not import users blueprint: {e}")
    
    try:
        from agents.routes import agents_bp
        app.register_blueprint(agents_bp, url_prefix='/agents')
        logger.info("Registered agents blueprint")
    except ImportError as e:
        logger.warning(f"Could not import agents blueprint: {e}")
    
    try:
        from coins.routes import coins_bp
        app.register_blueprint(coins_bp, url_prefix='/coins')
        logger.info("Registered coins blueprint")
    except ImportError as e:
        logger.warning(f"Could not import coins blueprint: {e}")
    
    try:
        from creditors.routes import creditors_bp
        app.register_blueprint(creditors_bp, url_prefix='/creditors')
        logger.info("Registered creditors blueprint")
    except ImportError as e:
        logger.warning(f"Could not import creditors blueprint: {e}")
    
    try:
        from dashboard.routes import dashboard_bp
        app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
        logger.info("Registered dashboard blueprint")
    except ImportError as e:
        logger.warning(f"Could not import dashboard blueprint: {e}")
    
    try:
        from debtors.routes import debtors_bp
        app.register_blueprint(debtors_bp, url_prefix='/debtors')
        logger.info("Registered debtors blueprint")
    except ImportError as e:
        logger.warning(f"Could not import debtors blueprint: {e}")
    
    try:
        from inventory.routes import inventory_bp
        app.register_blueprint(inventory_bp, url_prefix='/inventory')
        logger.info("Registered inventory blueprint")
    except ImportError as e:
        logger.warning(f"Could not import inventory blueprint: {e}")
    
    try:
        from payments.routes import payments_bp
        app.register_blueprint(payments_bp, url_prefix='/payments')
        logger.info("Registered payments blueprint")
    except ImportError as e:
        logger.warning(f"Could not import payments blueprint: {e}")
    
    try:
        from receipts.routes import receipts_bp
        app.register_blueprint(receipts_bp, url_prefix='/receipts')
        logger.info("Registered receipts blueprint")
    except ImportError as e:
        logger.warning(f"Could not import receipts blueprint: {e}")
    
    try:
        from reports.routes import reports_bp
        app.register_blueprint(reports_bp, url_prefix='/reports')
        logger.info("Registered reports blueprint")
    except ImportError as e:
        logger.warning(f"Could not import reports blueprint: {e}")
    
    try:
        from settings.routes import settings_bp
        app.register_blueprint(settings_bp, url_prefix='/settings')
        logger.info("Registered settings blueprint")
    except ImportError as e:
        logger.warning(f"Could not import settings blueprint: {e}")
    
    try:
        from admin.routes import admin_bp
        app.register_blueprint(admin_bp, url_prefix='/admin')
        logger.info("Registered admin blueprint")
    except ImportError as e:
        logger.warning(f"Could not import admin blueprint: {e}")
    
    # Register personal finance blueprints
    try:
        from personal.bill import bill_bp
        from personal.budget import budget_bp
        from personal.emergency_fund import emergency_fund_bp
        from personal.financial_health import financial_health_bp
        from personal.learning_hub import learning_hub_bp
        from personal.net_worth import net_worth_bp
        from personal.quiz import quiz_bp
        
        app.register_blueprint(bill_bp, url_prefix='/personal/bill')
        app.register_blueprint(budget_bp, url_prefix='/personal/budget')
        app.register_blueprint(emergency_fund_bp, url_prefix='/personal/emergency_fund')
        app.register_blueprint(financial_health_bp, url_prefix='/personal/financial_health')
        app.register_blueprint(learning_hub_bp, url_prefix='/personal/learning_hub')
        app.register_blueprint(net_worth_bp, url_prefix='/personal/net_worth')
        app.register_blueprint(quiz_bp, url_prefix='/personal/quiz')
        logger.info("Registered all personal finance blueprints")
    except ImportError as e:
        logger.error(f"Could not import personal finance blueprints: {e}")
    
    # Jinja2 globals and filters
    app.jinja_env.globals.update(
        FACEBOOK_URL=app.config.get('FACEBOOK_URL', 'https://www.facebook.com'),
        TWITTER_URL=app.config.get('TWITTER_URL', 'https://www.twitter.com'),
        LINKEDIN_URL=app.config.get('LINKEDIN_URL', 'https://www.linkedin.com'),
        FEEDBACK_FORM_URL=app.config.get('FEEDBACK_FORM_URL', '#'),
        WAITLIST_FORM_URL=app.config.get('WAITLIST_FORM_URL', '#'),
        CONSULTANCY_FORM_URL=app.config.get('CONSULTANCY_FORM_URL', '#'),
        trans=trans,
        trans_function=trans_function
    )
    
    @app.template_filter('safe_nav')
    def safe_nav(value):
        try:
            return value
        except Exception as e:
            logger.error(f"Navigation rendering error: {str(e)}", exc_info=True)
            return ''
    
    @app.template_filter('format_number')
    def format_number(value):
        try:
            if isinstance(value, (int, float)):
                return f"{float(value):,.2f}"
            return str(value)
        except (ValueError, TypeError) as e:
            logger.warning(f"Error formatting number {value}: {str(e)}")
            return str(value)
    
    @app.template_filter('format_currency')
    def format_currency(value):
        try:
            value = float(value)
            locale = session.get('lang', 'en')
            symbol = '₦'
            if value.is_integer():
                return f"{symbol}{int(value):,}"
            return f"{symbol}{value:,.2f}"
        except (TypeError, ValueError) as e:
            logger.warning(f"Error formatting currency {value}: {str(e)}")
            return str(value)
    
    @app.template_filter('format_datetime')
    def format_datetime(value):
        try:
            locale = session.get('lang', 'en')
            format_str = '%B %d, %Y, %I:%M %p' if locale == 'en' else '%d %B %Y, %I:%M %p'
            if isinstance(value, datetime):
                return value.strftime(format_str)
            elif isinstance(value, date):
                return value.strftime('%B %d, %Y' if locale == 'en' else '%d %B %Y')
            elif isinstance(value, str):
                parsed = datetime.strptime(value, '%Y-%m-%d')
                return parsed.strftime(format_str)
            return str(value)
        except Exception as e:
            logger.warning(f"Error formatting datetime {value}: {str(e)}")
            return str(value)
    
    @app.template_filter('format_date')
    def format_date(value):
        try:
            locale = session.get('lang', 'en')
            format_str = '%Y-%m-%d' if locale == 'en' else '%d-%m-%Y'
            if isinstance(value, datetime):
                return value.strftime(format_str)
            elif isinstance(value, date):
                return value.strftime(format_str)
            elif isinstance(value, str):
                parsed = datetime.strptime(value, '%Y-%m-%d').date()
                return parsed.strftime(format_str)
            return str(value)
        except Exception as e:
            logger.warning(f"Error formatting date {value}: {str(e)}")
            return str(value)
    
    @app.template_filter('trans')
    def trans_filter(key, **kwargs):
        lang = session.get('lang', 'en')
        translation = trans(key, lang=lang, **kwargs)
        if translation == key:
            logger.warning(f"Missing translation for key='{key}' in lang='{lang}'")
            return key
        return translation
    
    @app.context_processor
    def inject_globals():
        lang = session.get('lang', 'en')
        def context_trans(key, **kwargs):
            used_lang = kwargs.pop('lang', lang)
            return trans(
                key,
                lang=used_lang,
                logger=g.get('logger', logger) if has_request_context() else logger,
                **kwargs
            )
        return {
            'google_client_id': app.config.get('GOOGLE_CLIENT_ID', ''),
            'trans': context_trans,
            'current_year': datetime.now().year,
            'LINKEDIN_URL': app.config.get('LINKEDIN_URL', '#'),
            'TWITTER_URL': app.config.get('TWITTER_URL', '#'),
            'FACEBOOK_URL': app.config.get('FACEBOOK_URL', '#'),
            'FEEDBACK_FORM_URL': app.config.get('FEEDBACK_FORM_URL', '#'),
            'WAITLIST_FORM_URL': app.config.get('WAITLIST_FORM_URL', '#'),
            'CONSULTANCY_FORM_URL': app.config.get('CONSULTANCY_FORM_URL', '#'),
            'current_lang': lang,
            'current_user': current_user if has_request_context() else None,
            'csrf_token': csrf.generate_csrf
        }
    
    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com;"
        )
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    # Routes
    @app.route('/', methods=['GET', 'HEAD'])
    def index():
        lang = session.get('lang', 'en')
        logger.info(f"Serving index page, authenticated: {current_user.is_authenticated}, user: {current_user.username if current_user.is_authenticated and hasattr(current_user, 'username') else 'None'}")
        if request.method == 'HEAD':
            return '', 200
        if current_user.is_authenticated:
            if current_user.role == 'agent':
                return redirect(url_for('agents_bp.dashboard'))
            elif current_user.role == 'trader':
                return redirect(url_for('dashboard_bp.index'))
            elif current_user.role == 'admin':
                return redirect(url_for('admin_bp.dashboard'))
            elif current_user.role == 'personal':
                return redirect(url_for('general_dashboard'))
            else:
                return render_template('general/home.html', t=trans, lang=lang)
        try:
            courses = app.config.get('COURSES', [])
            logger.info(f"Retrieved {len(courses)} courses")
            return render_template(
                'index.html',
                t=trans,
                courses=courses,
                lang=lang,
                sample_courses=courses
            )
        except Exception as e:
            logger.error(f"Error in index route: {str(e)}", exc_info=True)
            flash(trans('learning_hub_error_message', default='An error occurred'), 'danger')
            return render_template('error.html', t=trans, lang=lang, error=str(e)), 500
    
    @app.route('/general_dashboard')
    @ensure_session_id
    def general_dashboard():
        lang = session.get('lang', 'en')
        logger.info(f"Serving general_dashboard for {'anonymous' if session.get('is_anonymous') else 'authenticated' if current_user.is_authenticated else 'no_session'} user")
        data = {}
        try:
            filter_kwargs = {'user_id': current_user.id} if current_user.is_authenticated else {'session_id': session.get('sid', 'no-session-id')}
            fh_records = get_financial_health(get_mongo_db(), filter_kwargs)
            fh_records = [to_dict_financial_health(fh) for fh in fh_records]
            data['financial_health'] = fh_records[0] if fh_records else {'score': None, 'status': None}
            budget_records = get_budgets(get_mongo_db(), filter_kwargs)
            budget_records = [to_dict_budget(b) for b in budget_records]
            data['budget'] = budget_records[0] if budget_records else {'surplus_deficit': None, 'savings_goal': None}
            bills = get_bills(get_mongo_db(), filter_kwargs)
            bills = [to_dict_bill(b) for b in bills]
            total_amount = sum(bill['amount'] for bill in bills if bill['amount'] is not None) if bills else 0
            unpaid_amount = sum(bill['amount'] for bill in bills if bill['amount'] is not None and bill['status'].lower() != 'paid') if bills else 0
            data['bills'] = {'bills': bills, 'total_amount': total_amount, 'unpaid_amount': unpaid_amount}
            nw_records = get_net_worth(get_mongo_db(), filter_kwargs)
            nw_records = [to_dict_net_worth(nw) for nw in nw_records]
            data['net_worth'] = nw_records[0] if nw_records else {'net_worth': None, 'total_assets': None}
            ef_records = get_emergency_funds(get_mongo_db(), filter_kwargs)
            ef_records = [to_dict_emergency_fund(ef) for ef in ef_records]
            data['emergency_fund'] = ef_records[0] if ef_records else {'target_amount': None, 'savings_gap': None}
            lp_records = get_learning_progress(get_mongo_db(), filter_kwargs)
            data['learning_progress'] = {lp['course_id']: to_dict_learning_progress(lp) for lp in lp_records} if lp_records else {}
            quiz_records = get_quiz_results(get_mongo_db(), filter_kwargs)
            quiz_records = [to_dict_quiz_result(qr) for qr in quiz_records]
            data['quiz'] = quiz_records[0] if quiz_records else {'personality': None, 'score': None}
            logger.info(f"Retrieved data for session {session.get('sid', 'no-session-id')}")
            return render_template('personal/GENERAL/general_dashboard.html', data=data, t=trans, lang=lang)
        except Exception as e:
            logger.error(f"Error in general_dashboard: {str(e)}", exc_info=True)
            flash(trans('global_error_message', default='An error occurred'), 'danger')
            default_data = {
                'financial_health': {'score': None, 'status': None},
                'budget': {'surplus_deficit': None, 'savings_goal': None},
                'bills': {'bills': [], 'total_amount': 0, 'unpaid_amount': 0},
                'net_worth': {'net_worth': None, 'total_assets': None},
                'emergency_fund': {'target_amount': None, 'savings_gap': None},
                'learning_progress': {},
                'quiz': {'personality': None, 'score': None}
            }
            return render_template('personal/GENERAL/general_dashboard.html', data=default_data, t=trans, lang=lang), 500
    
    @app.route('/logout')
    def logout():
        lang = session.get('lang', 'en')
        logger.info("Logging out user")
        try:
            session_lang = session.get('lang', 'en')
            session.clear()
            session['lang'] = session_lang
            flash(trans('learning_hub_success_logout', default='Successfully logged out'), 'success')
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Error in logout: {str(e)}", exc_info=True)
            flash(trans('global_error_message', default='An error occurred'), 'danger')
            return redirect(url_for('index'))
    
    @app.route('/about')
    def about():
        lang = session.get('lang', 'en')
        logger.info("Serving about page")
        return render_template('general/about.html', t=trans, lang=lang)
    
    @app.route('/contact')
    def contact():
        lang = session.get('lang', 'en')
        return render_template('general/contact.html', t=trans, lang=lang)
    
    @app.route('/privacy')
    def privacy():
        lang = session.get('lang', 'en')
        return render_template('general/privacy.html', t=trans, lang=lang)
    
    @app.route('/terms')
    def terms():
        lang = session.get('lang', 'en')
        return render_template('general/terms.html', t=trans, lang=lang)
    
    @app.route('/health')
    def health():
        logger.info("Health check")
        status = {"status": "healthy"}
        try:
            if not check_mongodb_connection(mongo_client, app):
                raise RuntimeError("MongoDB connection unavailable")
            get_mongo_db().command('ping')
            return jsonify(status), 200
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}", exc_info=True)
            status["status"] = "unhealthy"
            status["details"] = str(e)
            return jsonify(status), 500
    
    @app.route('/api/translations/<lang>')
    def get_translations(lang):
        valid_langs = ['en', 'ha']
        if lang in valid_langs:
            return jsonify({'translations': app.config.get('TRANSLATIONS', {}).get(lang, app.config.get('TRANSLATIONS', {}).get('en', {}))})
        return jsonify({'translations': app.config.get('TRANSLATIONS', {}).get('en', {})}), 400
    
    @app.route('/set_language/<lang>')
    def set_language(lang):
        valid_langs = ['en', 'ha']
        new_lang = lang if lang in valid_langs else 'en'
        try:
            session['lang'] = new_lang
            if current_user.is_authenticated:
                get_mongo_db().users.update_one({'_id': current_user.id}, {'$set': {'language': new_lang}})
            logger.info(f"Language set to {new_lang}")
            flash(trans('learning_hub_success_language_updated', default='Language updated successfully'), 'success')
        except Exception as e:
            logger.error(f"Session operation failed: {str(e)}")
            flash(trans('invalid_language', default='Invalid language'), 'danger')
        return redirect(request.referrer or url_for('index'))
    
    @app.route('/acknowledge_consent', methods=['POST'])
    def acknowledge_consent():
        if request.method != 'POST':
            logger.warning(f"Invalid method {request.method} for consent acknowledgement")
            return '', 400
        try:
            session['consent_acknowledged'] = {
                'status': True,
                'timestamp': datetime.utcnow().isoformat(),
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent')
            }
            logger.info(f"Consent acknowledged for session {session.get('sid', 'no-session-id')} from IP {request.remote_addr}")
        except Exception as e:
            logger.error(f"Session operation failed: {str(e)}")
        response = make_response('', 204)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    
    # Existing accounting API routes
    @app.route('/api/debt-summary')
    @login_required
    def debt_summary():
        try:
            db = get_mongo_db()
            user_id = current_user.id
            creditors_pipeline = [
                {'$match': {'user_id': user_id, 'type': 'creditor'}},
                {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
            ]
            creditors_result = list(db.records.aggregate(creditors_pipeline))
            total_i_owe = creditors_result[0]['total'] if creditors_result else 0
            debtors_pipeline = [
                {'$match': {'user_id': user_id, 'type': 'debtor'}},
                {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
            ]
            debtors_result = list(db.records.aggregate(debtors_pipeline))
            total_i_am_owed = debtors_result[0]['total'] if debtors_result else 0
            return jsonify({
                'totalIOwe': total_i_owe,
                'totalIAmOwed': total_i_am_owed
            })
        except Exception as e:
            logger.error(f"Error fetching debt summary: {str(e)}")
            return jsonify({'error': 'Failed to fetch debt summary'}), 500
    
    @app.route('/api/cashflow-summary')
    @login_required
    def cashflow_summary():
        try:
            db = get_mongo_db()
            user_id = current_user.id
            now = datetime.utcnow()
            month_start = datetime(now.year, now.month, 1)
            next_month = month_start.replace(month=month_start.month + 1) if month_start.month < 12 else month_start.replace(year=month_start.year + 1, month=1)
            receipts_pipeline = [
                {'$match': {'user_id': user_id, 'type': 'receipt', 'created_at': {'$gte': month_start, '$lt': next_month}}},
                {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
            ]
            receipts_result = list(db.cashflows.aggregate(receipts_pipeline))
            total_receipts = receipts_result[0]['total'] if receipts_result else 0
            payments_pipeline = [
                {'$match': {'user_id': user_id, 'type': 'payment', 'created_at': {'$gte': month_start, '$lt': next_month}}},
                {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
            ]
            payments_result = list(db.cashflows.aggregate(payments_pipeline))
            total_payments = payments_result[0]['total'] if payments_result else 0
            net_cashflow = total_receipts - total_payments
            return jsonify({
                'netCashflow': net_cashflow,
                'totalReceipts': total_receipts,
                'totalPayments': total_payments
            })
        except Exception as e:
            logger.error(f"Error fetching cashflow summary: {str(e)}")
            return jsonify({'error': 'Failed to fetch cashflow summary'}), 500
    
    @app.route('/api/inventory-summary')
    @login_required
    def inventory_summary():
        try:
            db = get_mongo_db()
            user_id = current_user.id
            pipeline = [
                {'$match': {'user_id': user_id}},
                {'$addFields': {
                    'item_value': {
                        '$multiply': [
                            '$qty',
                            {'$ifNull': ['$buying_price', 0]}
                        ]
                    }
                }},
                {'$group': {'_id': None, 'totalValue': {'$sum': '$item_value'}}}
            ]
            result = list(db.inventory.aggregate(pipeline))
            total_value = result[0]['totalValue'] if result else 0
            return jsonify({
                'totalValue': total_value
            })
        except Exception as e:
            logger.error(f"Error fetching inventory summary: {str(e)}")
            return jsonify({'error': 'Failed to fetch inventory summary'}), 500
    
    @app.route('/api/recent-activity')
    @login_required
    def recent_activity():
        try:
            db = get_mongo_db()
            user_id = current_user.id
            activities = []
            recent_records = list(db.records.find(
                {'user_id': user_id}
            ).sort('created_at', -1).limit(3))
            for record in recent_records:
                activity_type = 'debt_added'
                description = f"Added {record['type']}: {record['name']}"
                activities.append({
                    'type': activity_type,
                    'description': description,
                    'amount': record['amount_owed'],
                    'timestamp': record['created_at']
                })
            recent_cashflows = list(db.cashflows.find(
                {'user_id': user_id}
            ).sort('created_at', -1).limit(3))
            for cashflow in recent_cashflows:
                activity_type = 'money_in' if cashflow['type'] == 'receipt' else 'money_out'
                description = f"{'Received' if cashflow['type'] == 'receipt' else 'Paid'} {cashflow['party_name']}"
                activities.append({
                    'type': activity_type,
                    'description': description,
                    'amount': cashflow['amount'],
                    'timestamp': cashflow['created_at']
                })
            activities.sort(key=lambda x: x['timestamp'], reverse=True)
            activities = activities[:5]
            for activity in activities:
                activity['timestamp'] = activity['timestamp'].isoformat()
            return jsonify(activities)
        except Exception as e:
            logger.error(f"Error fetching recent activity: {str(e)}")
            return jsonify({'error': 'Failed to fetch recent activity'}), 500
    
    @app.route('/api/notifications/count')
    @login_required
    def notification_count():
        try:
            db = get_mongo_db()
            user_id = current_user.id
            count = db.reminder_logs.count_documents({
                'user_id': user_id,
                'read_status': False
            })
            return jsonify({'count': count})
        except Exception as e:
            logger.error(f"Error fetching notification count: {str(e)}")
            return jsonify({'error': 'Failed to fetch notification count'}), 500
    
    @app.route('/api/notifications')
    @login_required
    def notifications():
        try:
            db = get_mongo_db()
            user_id = current_user.id
            notifications = list(db.reminder_logs.find({
                'user_id': user_id
            }).sort('sent_at', -1).limit(10))
            notification_ids = [n['notification_id'] for n in notifications if not n.get('read_status', False)]
            if notification_ids:
                db.reminder_logs.update_many(
                    {'notification_id': {'$in': notification_ids}},
                    {'$set': {'read_status': True}}
                )
            result = [{
                'id': str(n['notification_id']),
                'message': n['message'],
                'type': n['type'],
                'timestamp': n['sent_at'].isoformat(),
                'read': n.get('read_status', False)
            } for n in notifications]
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error fetching notifications: {str(e)}")
            return jsonify({'error': 'Failed to fetch notifications'}), 500
    
    @app.route('/feedback', methods=['GET', 'POST'])
    @ensure_session_id
    def feedback():
        lang = session.get('lang', 'en')
        logger.info("Handling feedback")
        tool_options = [
            ['profile', trans('profile_section', default='Profile')],
            ['coins', trans('coins_section', default='Coins')],
            ['debtors', trans('debtors_section', default='People')],
            ['creditors', trans('creditors_section')],
            ['receipts', trans('receipts_section', default='Receipts')],
            ['payment', trans('payments_section', default='Payments')],
            ['inventory', trans('inventory_section', default='Inventory')],
            ['report', trans('report_section', default='Reports')],
            ['financial_health', trans('financial_health_section', default='Financial Health')],
            ['budget', trans('budget_section', default='Budget')],
            ['bill', trans('bill_section', default='Bill')],
            ['net_worth', trans('net_worth_section', default='Net Worth')],
            ['emergency_fund', trans('emergency_fund_section', default='Emergency Fund')],
            ['learning', trans('learning_section', default='Learning')],
            ['quiz', trans('quiz_section', default='Quiz')]
        ]
        if request.method == 'POST':
            try:
                from models import create_feedback
                tool_name = request.form.get('tool_name')
                rating = request.form.get('rating')
                comment = request.form.get('comment', '').strip()
                valid_tools = [option[0] for option in tool_options]
                if not tool_name or tool_name not in valid_tools:
                    logger.error(f"Invalid feedback tool: {tool_name}")
                    flash(trans('error_feedback_form', default='Please select a valid tool'), 'danger')
                    return render_template('personal/GENERAL/feedback.html', t=trans, lang=lang, tool_options=tool_options)
                if not rating or not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
                    logger.error(f"Invalid rating: {rating}")
                    flash(trans('error_feedback_rating', default='Please provide a rating between 1 and 5'), 'danger')
                    return render_template('personal/GENERAL/feedback.html', t=trans, lang=lang, tool_options=tool_options)
                if current_user.is_authenticated:
                    from coins.routes import get_user_query
                    query = get_user_query(str(current_user.id))
                    result = get_mongo_db().users.update_one(query, {'$inc': {'coin_balance': -1}})
                    if result.matched_count == 0:
                        raise ValueError(f"No user found for ID {current_user.id}")
                    get_mongo_db().coin_transactions.insert_one({
                        'user_id': str(current_user.id),
                        'amount': -1,
                        'type': 'spend',
                        'ref': f"FEEDBACK_{datetime.utcnow().isoformat()}",
                        'date': datetime.utcnow()
                    })
                feedback_entry = {
                    'user_id': current_user.id if current_user.is_authenticated else None,
                    'session_id': session.get('sid', 'no-session-id'),
                    'tool_name': tool_name,
                    'rating': int(rating),
                    'comment': comment or None,
                    'timestamp': datetime.utcnow()
                }
                create_feedback(get_mongo_db(), feedback_entry)
                get_mongo_db().audit_logs.insert_one({
                    'admin_id': 'system',
                    'action': 'submit_feedback',
                    'details': {'user_id': str(current_user.id) if current_user.is_authenticated else None, 'tool_name': tool_name},
                    'timestamp': datetime.utcnow()
                })
                logger.info(f"Feedback submitted: tool={tool_name}, rating={rating}, session={session.get('sid', 'no-session-id')}")
                flash(trans('success_feedback', default='Thank you for your feedback!'), 'success')
                return redirect(url_for('index'))
            except ValueError as e:
                logger.error(f"User not found: {str(e)}")
                flash(trans('user_not_found', default='User not found'), 'danger')
            except Exception as e:
                logger.error(f"Error processing feedback: {str(e)}", exc_info=True)
                flash(trans('error_feedback', default='Error occurred during feedback submission'), 'danger')
                return render_template('personal/GENERAL/feedback.html', t=trans, lang=lang, tool_options=tool_options), 500
        logger.info("Rendering feedback index template")
        return render_template('personal/GENERAL/feedback.html', t=trans, lang=lang, tool_options=tool_options)
    
    @app.route('/setup', methods=['GET'])
    @limiter.limit("10 per minute")
    def setup_database_route():
        setup_key = request.args.get('key')
        if setup_key != os.getenv('SETUP_KEY', 'setup-secret'):
            return render_template('errors/403.html', content=trans('forbidden_access', default='Access denied')), 403
        try:
            initialize_database(app)
            flash(trans('database_setup_success', default='Database setup successful'), 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(trans('database_setup_error', default='An error occurred during database setup'), 'danger')
            return render_template('errors/500.html', content=trans('internal_error', default='Internal server error')), 500
    
    @app.route('/static/<path:filename>')
    def static_files(filename):
        response = send_from_directory('static', filename)
        response.headers['Cache-Control'] = 'public, max-age=31536000'
        return response
    
    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(app.static_folder, 'favicon.ico')
    
    @app.route('/service-worker.js')
    def service_worker():
        return app.send_static_file('service-worker.js')
    
    @app.route('/manifest.json')
    def manifest():
        return {
            'name': 'FiCore',
            'short_name': 'FiCore',
            'description': 'Manage your finances with ease',
            'theme_color': '#007bff',
            'background_color': '#ffffff',
            'display': 'standalone',
            'scope': '/',
            'start_url': '/',
            'icons': [
                {'src': '/static/icons/icon-192x192.png', 'sizes': '192x192', 'type': 'image/png'},
                {'src': '/static/icons/icon-512x512.png', 'sizes': '512x512', 'type': 'image/png'}
            ]
        }
    
    @app.route('/robots.txt')
    def robots_txt():
        return Response("User-agent: *\nDisallow: /", mimetype='text/plain')
    
    @app.errorhandler(403)
    def forbidden(e):
        lang = session.get('lang', 'en')
        return render_template('errors/403.html', message=trans('forbidden', default='Forbidden'), t=trans, lang=lang), 403
    
    @app.errorhandler(404)
    def page_not_found(e):
        lang = session.get('lang', 'en')
        logger.error(f"Error 404: {str(e)}")
        return render_template('errors/404.html', message=trans('page_not_found', default='Page not found'), t=trans, lang=lang), 404
    
    @app.errorhandler(500)
    def internal_server_error(e):
        lang = session.get('lang', 'en')
        logger.error(f"Server error: {str(e)}", exc_info=True)
        return render_template('errors/500.html', message=trans('internal_server_error', default='Internal server error'), t=trans, lang=lang), 500
    
    @app.errorhandler(csrf.CSRFError)
    def handle_csrf_error(e):
        lang = session.get('lang', 'en')
        logger.error(f"CSRF error: {str(e)}")
        return jsonify({'error': 'CSRF token invalid'}), 400
    
    @app.before_request
    def before_request():
        if request.path.startswith('/static/') or request.path in [
            '/manifest.json', '/service-worker.js', '/favicon.ico', '/robots.txt'
        ]:
            logger.info(f"Skipping session setup for request: {request.path}")
            return
        logger.info(f"Starting before_request for path: {request.path}")
        try:
            if 'sid' not in session:
                session['sid'] = session.sid
                session['is_anonymous'] = not current_user.is_authenticated
                logger.info(f"Session ID set: {session['sid']}, is_anonymous: {session['is_anonymous']}")
            if 'lang' not in session:
                session['lang'] = request.accept_languages.best_match(['en', 'ha'], 'en')
                logger.info(f"Set default language to {session['lang']}")
            g.logger = logger
            if current_user.is_authenticated:
                if 'session_id' not in session:
                    session['session_id'] = str(uuid.uuid4())
                db = get_mongo_db()
                user = db.users.find_one({'_id': current_user.id})
                if user and not user.get('setup_complete', False):
                    allowed_endpoints = [
                        'users_bp.personal_setup_wizard',
                        'users_bp.setup_wizard',
                        'users_bp.agent_setup_wizard',
                        'users_bp.logout',
                        'settings_bp.profile',
                        'coins_bp.purchase',
                        'coins_bp.get_balance',
                        'set_language'
                    ]
                    if request.endpoint not in allowed_endpoints:
                        flash(trans('setup_required', default='Please complete your profile setup'), 'warning')
                        if current_user.role == 'agent':
                            return redirect(url_for('users_bp.agent_setup_wizard'))
                        return redirect(url_for('users_bp.personal_setup_wizard'))
        except Exception as e:
            logger.error(f"Error in before_request: {str(e)}", exc_info=True)
    
    return app

# Create the app instance for Gunicorn
app = create_app()

if __name__ == '__main__':
    # This allows running the app directly with python app.py for development
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_ENV') == 'development')