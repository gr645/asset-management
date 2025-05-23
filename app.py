from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_pymongo import PyMongo
from datetime import datetime
import pandas as pd
import os
from bson.objectid import ObjectId
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production

# Simplified MongoDB connection
try:
    app.config['MONGO_URI'] = 'mongodb://127.0.0.1:27017/asset_management'
    mongo = PyMongo(app)
    # Test connection
    mongo.db.command('ping')
    print("Successfully connected to MongoDB!")
except Exception as e:
    print(f"Error connecting to MongoDB: {str(e)}")
    print("Please make sure MongoDB is installed and running")
    raise e

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.password = user_data['password']
        self.email = user_data.get('email', '')
        self.is_admin = user_data.get('is_admin', False)
        self.department = user_data.get('department', '')

@login_manager.user_loader
def load_user(user_id):
    user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

def validate_email(email):
    pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    return re.match(pattern, email) is not None

def get_inventory_total(asset_type):
    inventory = mongo.db.inventory.find_one({'asset_type': asset_type})
    return inventory.get('total', 0)

def get_available_inventory(asset_type):
    inventory = mongo.db.inventory.find_one({'asset_type': asset_type})
    if not inventory:
        return 0
    
    # Count approved requests for this asset type
    approved_count = mongo.db.asset_requests.count_documents({
        'asset_type': asset_type,
        'status': 'Approved'
    })
    
    return inventory.get('total', 0) - approved_count

def log_to_excel(request_id, user_id, asset_type, justification, status, admin_comment):
    log_file = 'asset_requests_log.xlsx'
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    new_data = {
        'Request ID': [str(request_id)],
        'User ID': [str(user_id)],
        'Asset Type': [asset_type],
        'Justification': [justification],
        'Status': [status],
        'Admin Comment': [admin_comment],
        'Timestamp': [timestamp]
    }
    
    df_new = pd.DataFrame(new_data)
    
    if os.path.exists(log_file):
        df_existing = pd.read_excel(log_file)
        df_updated = pd.concat([df_existing, df_new], ignore_index=True) # Use ignore_index=True to reset index
    else:
        df_updated = df_new
    
    df_updated.to_excel(log_file, index=False)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'true'
        
        print(f"\nLogin attempt - Username: {username}, Is Admin: {is_admin}")
        
        # Find user
        user_data = mongo.db.users.find_one({'username': username})
        
        if not user_data:
            print(f"No user found with username: {username}")
            flash('Username not found', 'error')
            return render_template('login.html')
        
        print(f"Found user: {user_data}")
        
        # Check admin status
        if is_admin:
            if not user_data.get('is_admin', False):
                print("User is not an admin")
                flash('Invalid admin credentials', 'error')
                return render_template('login.html')
        else:
            if user_data.get('is_admin', False):
                print("Admin trying to use regular login")
                flash('Please use admin login form', 'error')
                return render_template('login.html')
        
        # Check password
        if user_data['password'] == password:
            print("Password correct, logging in")
            user = User(user_data)
            login_user(user)
            return redirect(url_for('dashboard'))
        
        print("Invalid password")
        flash('Invalid password', 'error')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        requests = list(mongo.db.asset_requests.find().sort('created_at', -1))
        total_requests = mongo.db.asset_requests.count_documents({})
        pending_requests = mongo.db.asset_requests.count_documents({'status': 'Pending'})
        approved_requests = mongo.db.asset_requests.count_documents({'status': 'Approved'})
        disapproved_requests = mongo.db.asset_requests.count_documents({'status': 'Disapproved'})
        recent_requests = list(mongo.db.asset_requests.find().sort('created_at', -1).limit(5))
        
        inventory_status = {}
        # Get inventory status for asset types that have been requested or are in inventory
        asset_types_in_requests = mongo.db.asset_requests.distinct('asset_type')
        asset_types_in_inventory = mongo.db.inventory.distinct('asset_type')
        all_asset_types = list(set(asset_types_in_requests + asset_types_in_inventory))

        for asset_type in all_asset_types:
             inventory_status[asset_type] = get_available_inventory(asset_type)

    else:
        requests = list(mongo.db.asset_requests.find({'user_id': current_user.id}).sort('created_at', -1))
        total_requests = mongo.db.asset_requests.count_documents({'user_id': current_user.id})
        pending_requests = mongo.db.asset_requests.count_documents({'user_id': current_user.id, 'status': 'Pending'})
        approved_requests = mongo.db.asset_requests.count_documents({'user_id': current_user.id, 'status': 'Approved'})
        disapproved_requests = mongo.db.asset_requests.count_documents({'user_id': current_user.id, 'status': 'Disapproved'})
        recent_requests = list(mongo.db.asset_requests.find({'user_id': current_user.id}).sort('created_at', -1).limit(5))
        
        inventory_status = {}
        # Get inventory status for asset types that the user has requested
        asset_types_in_user_requests = mongo.db.asset_requests.distinct('asset_type', {'user_id': current_user.id})
        for asset_type in asset_types_in_user_requests:
             inventory_status[asset_type] = get_available_inventory(asset_type)


    return render_template('dashboard.html',
                           requests=requests,
                           inventory_status=inventory_status,
                           total_requests=total_requests,
                           pending_requests=pending_requests,
                           approved_requests=approved_requests,
                           disapproved_requests=disapproved_requests,
                           recent_requests=recent_requests,
                           get_inventory_total=get_inventory_total)

@app.route('/submit_request', methods=['GET', 'POST'])
@login_required
def submit_request():
    if request.method == 'POST':
        asset_type = request.form.get('asset_type')
        justification = request.form.get('justification')
        
        # Check if asset is available
        available = get_available_inventory(asset_type)
        if available <= 0:
            flash('Sorry, this asset is currently out of stock')
            return render_template('submit_request.html') # Render template again to show the message
        
        new_request = {
            'user_id': current_user.id,
            'username': current_user.username,
            'department': current_user.department,
            'asset_type': asset_type,
            'justification': justification,
            'status': 'Pending',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
            'admin_comment': ''
        }
        
        mongo.db.asset_requests.insert_one(new_request) # Insert the new request
        flash('Request submitted successfully')
        return redirect(url_for('dashboard'))
        
    # For GET request, render the template
    # Fetch available asset types for the dropdown
    available_asset_types = [item['asset_type'] for item in mongo.db.inventory.find({}, {'asset_type': 1})]
    available_asset_types.sort()

    return render_template('submit_request.html', available_asset_types=available_asset_types)

@app.route('/review_request/<request_id>', methods=['POST'])
@login_required
def review_request(request_id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    request_obj = mongo.db.asset_requests.find_one({'_id': ObjectId(request_id)})
    if not request_obj:
        flash('Request not found')
        return redirect(url_for('dashboard'))
    
    action = request.form.get('action')
    admin_comment = request.form.get('admin_comment', '')
    
    # Check if asset is available when approving and status is Pending
    if action == 'approve' and request_obj['status'] == 'Pending':
        available = get_available_inventory(request_obj['asset_type'])
        if available <= 0:
            flash('Cannot approve: No inventory available')
            return redirect(url_for('dashboard'))
    
    status = 'Approved' if action == 'approve' else 'Disapproved'
    
    # Only update if status is Pending
    if request_obj['status'] == 'Pending':
        mongo.db.asset_requests.update_one(
            {'_id': ObjectId(request_id)},
            {
                '$set': {
                    'status': status,
                    'admin_comment': admin_comment,
                    'updated_at': datetime.utcnow()
                }
            }
        )
    
        log_to_excel(
            request_id,
            request_obj['user_id'],
            request_obj['asset_type'],
            request_obj['justification'],
            status,
            admin_comment
        )
    else:
        flash(f"Request {request_obj['status'].lower()} already. Cannot change status.")
    
    flash(f'Request {action}d successfully')
    return redirect(url_for('dashboard'))

@app.route('/manage_inventory', methods=['GET', 'POST'])
@login_required
def manage_inventory():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        asset_type = request.form.get('asset_type')
        total = int(request.form.get('total', 0))
        
        if not asset_type or total < 0:
            flash('Invalid input')
            return redirect(url_for('manage_inventory'))

        # Update or insert inventory
        mongo.db.inventory.update_one(
            {'asset_type': asset_type},
            {'$inc': {'total': total}},
            upsert=True
        )
        flash(f'Inventory updated for {asset_type}')
        return redirect(url_for('manage_inventory'))
    
    inventory = list(mongo.db.inventory.find())
    # Fetch asset types from asset_requests for a comprehensive list
    asset_types_in_requests = mongo.db.asset_requests.distinct('asset_type')
    # Combine asset types from inventory and requests for the dropdown
    all_asset_types = sorted(list(set([item['asset_type'] for item in inventory] + asset_types_in_requests)))

    # Calculate available inventory for display
    inventory_display = []
    for item in inventory:
        available = get_available_inventory(item['asset_type'])
        inventory_display.append({
            'asset_type': item['asset_type'],
            'total': item['total'],
            'available': available,
            'allocated': item['total'] - available
        })

    return render_template('manage_inventory.html', inventory=inventory_display, all_asset_types=all_asset_types, get_available_inventory=get_available_inventory)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/generate_report')
@login_required
def generate_report():
    if not current_user.is_admin:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))

    # Fetch all asset requests
    requests_data = list(mongo.db.asset_requests.find({}))

    if not requests_data:
        flash('No asset requests found to generate report.', 'info')
        return redirect(url_for('dashboard'))

    # Prepare data for DataFrame
    # Ensure all required fields are present, provide default empty string if missing
    processed_data = []
    for req in requests_data:
        processed_data.append({
            'Request ID': str(req.get('_id', '')),
            'User ID': req.get('user_id', ''),
            'Username': req.get('username', ''),
            'Department': req.get('department', ''),
            'Asset Type': req.get('asset_type', ''),
            'Justification': req.get('justification', ''),
            'Status': req.get('status', ''),
            'Admin Comment': req.get('admin_comment', ''),
            'Created At': req.get('created_at', datetime.min).strftime('%Y-%m-%d %H:%M:%S') if isinstance(req.get('created_at'), datetime) else '',
            'Updated At': req.get('updated_at', datetime.min).strftime('%Y-%m-%d %H:%M:%S') if isinstance(req.get('updated_at'), datetime) else '',
        })

    # Create a pandas DataFrame
    df = pd.DataFrame(processed_data)

    # Generate Excel file
    excel_file = 'asset_requests_report.xlsx'
    df.to_excel(excel_file, index=False)

    # Send the file as a response
    return send_file(excel_file, as_attachment=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        department = request.form.get('department')

        if not username or not password or not email or not department:
            flash('All fields are required', 'error')
            return render_template('login.html')

        if not validate_email(email):
            flash('Please enter a valid email address', 'error')
            return render_template('login.html')

        if mongo.db.users.find_one({'username': username}):
            flash('Username already exists', 'error')
            return render_template('login.html')

        if mongo.db.users.find_one({'email': email}):
            flash('Email already registered', 'error')
            return render_template('login.html')

        mongo.db.users.insert_one({
            'username': username,
            'password': password,  # In production, hash the password!
            'email': email,
            'is_admin': False,
            'department': department
        })
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('login.html')

if __name__ == '__main__':
    # Create initial users if they don't exist
    if mongo.db.users.count_documents({}) == 0:
        print("\nCreating initial users...")
        try:
            # First, drop the users collection to start fresh
            mongo.db.users.drop()
            
            # Create new users
            mongo.db.users.insert_many([
                {
                    'username': 'admin',
                    'password': 'admin123',
                    'email': 'admin@company.com',
                    'is_admin': True,
                    'department': 'IT'
                },
                {
                    'username': 'employee',
                    'password': 'employee123',
                    'email': 'employee@company.com',
                    'is_admin': False,
                    'department': 'IT'
                }
            ])
            print("Initial users created successfully")
            
            # Verify admin user was created
            admin = mongo.db.users.find_one({'username': 'admin'})
            print(f"Admin user created: {admin}")
            
        except Exception as e:
            print(f"Error creating initial users: {str(e)}")
    else:
        # Verify existing users
        admin = mongo.db.users.find_one({'username': 'admin'})
        print(f"\nExisting admin user: {admin}")
    
    app.run(debug=True)