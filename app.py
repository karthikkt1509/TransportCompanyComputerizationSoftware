from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import pytz
IST = pytz.timezone("Asia/Kolkata")
import uuid
import bcrypt
from functools import wraps
from sqlalchemy import CheckConstraint
from sqlalchemy import func

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import os
BASEDIR = os.path.abspath(os.path.dirname(__file__))


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASEDIR, 'instance', 'tccs.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'  # Change in production
app.config.setdefault('ADMIN_SIGNUP_CODE', '123')
db = SQLAlchemy(app)

# expose pytz/IST to Jinja templates
app.jinja_env.globals['pytz'] = pytz
app.jinja_env.globals['IST'] = IST

# Database Models
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # Manager or Employee
    branch_id = db.Column(db.String(36), db.ForeignKey('branch.id'), nullable=True)

# ----- Customer model (for signup/login and reuse) -----
class Customer(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # bcrypt-hashed
    phone = db.Column(db.String(30), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(IST))


class Consignment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    volume = db.Column(db.Float, nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    sender_name = db.Column(db.String(100), nullable=False)
    sender_address = db.Column(db.String(200), nullable=False)
    receiver_name = db.Column(db.String(100), nullable=False)
    receiver_address = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), default='Pending')
    charge = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(IST))
    dispatched_at = db.Column(db.DateTime, nullable=True)
    branch_id = db.Column(db.String(36), db.ForeignKey('branch.id'), nullable=False)

    # @validates('volume')
    

class Truck(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    location = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default='Available')
    capacity = db.Column(db.Float, default=500.0)
    last_updated = db.Column(db.DateTime, default=lambda: datetime.now(IST))
    branch_id = db.Column(db.String(36), db.ForeignKey('branch.id'), nullable=False)

class Branch(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    location = db.Column(db.String(100), nullable=False)

class ConsignmentTruck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    consignment_id = db.Column(db.String(36), db.ForeignKey('consignment.id'))
    truck_id = db.Column(db.String(36), db.ForeignKey('truck.id'))

class TruckAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    truck_id = db.Column(db.String(36), db.ForeignKey('truck.id'), nullable=False)
    driver_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)  # CHANGED
    assigned_at = db.Column(db.DateTime, default=lambda: datetime.now(IST))

# Authentication Decorator
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            user = db.session.get(User, session['user_id'])
            if not user or (role and user.role != role):
                return jsonify({'error': 'Unauthorized'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Helper Functions
def calculate_charge(volume, destination):
    base_rate = 10  # ₹10 per cubic meter (adjust if you want)
    distance_factor = 1.5 if destination != 'Capital' else 1.0
    return float(volume) * base_rate * distance_factor

def get_truck_volume(truck_id):
    total_volume = db.session.query(func.sum(Consignment.volume)).join(
        ConsignmentTruck
    ).filter(
        ConsignmentTruck.truck_id == truck_id
    ).scalar() or 0
    return total_volume

def check_truck_allocation(destination, branch_id):
    total_volume = db.session.query(func.sum(Consignment.volume)).filter(
        Consignment.destination == destination,
        Consignment.status == 'Pending',
        Consignment.branch_id == branch_id
    ).scalar() or 0
    if total_volume >= 500:
        truck = Truck.query.filter_by(branch_id=branch_id, status='Available').first()
        if truck:
            consignments = Consignment.query.filter_by(destination=destination, status='Pending', branch_id=branch_id).all()
            for consignment in consignments:
                consignment.status = 'Dispatched'
                consignment.dispatched_at = datetime.now(IST)
                db.session.add(ConsignmentTruck(consignment_id=consignment.id, truck_id=truck.id))
            truck.status = 'In-Transit'
            truck.last_updated = datetime.now(IST)
            db.session.commit()
            return truck, consignments
    return None, []


# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    General signup page for Manager, Employee, Driver, Customer.
    Note: creating Manager accounts requires ADMIN_SIGNUP_CODE for safety.
    """
    # no need to import _Customer here anymore
    if request.method == 'POST':
        data = request.form
        name = data.get('name') or data.get('username') or ''
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'Customer')  # default to Customer
        branch_id = data.get('branch_id') or None
        admin_code = data.get('admin_code')

        if not email or not password:
            return render_template('signup.html', error='Email and password required')

        # Prevent public creation of Manager unless admin code matches
        if role == 'Manager':
            if admin_code != app.config.get('ADMIN_SIGNUP_CODE'):
                return render_template('signup.html', error='Invalid admin code for Manager signup')

        # Check username/email uniqueness in User table
        if User.query.filter_by(username=email).first():
            return render_template('signup.html', error='Email already registered as user')

        # If role == 'Customer' and Customer model exists, ensure no duplicate customer email
        try:
            customer_model_exists = 'Customer' in globals()
        except Exception:
            customer_model_exists = False

        if role == 'Customer' and customer_model_exists:
            if Customer.query.filter_by(email=email).first():
                return render_template('signup.html', error='Customer email already registered')

        # Hash password & create User row
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_user = User(username=email, password=hashed, role=role, branch_id=branch_id)
        db.session.add(new_user)
        db.session.commit()

        # If Customer model exists, also create Customer record
        if role == 'Customer' and customer_model_exists:
            cust = Customer(name=name or email.split('@')[0], email=email, password=hashed, phone=data.get('phone'), address=data.get('address'))
            db.session.add(cust)
            db.session.commit()

        # Auto-login user (optional) — here we log them in and redirect to dashboard/login
        session['user_id'] = new_user.id
        return redirect(url_for('dashboard'))

    # GET: render signup form
    branches = Branch.query.all() if 'Branch' in globals() else []
    return render_template('signup.html', branches=branches)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        user = User.query.filter_by(username=data['username']).first()
        if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/consignments', methods=['POST'])
def add_consignment():
    user = db.session.get(User, session['user_id'])
    data = request.json
    branch_id = user.branch_id if user.role == 'Employee' else data.get('branch_id')
    if not branch_id:
        return jsonify({'error': 'Branch ID required'}), 400
    try:
        volume = float(data['volume'])
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid volume value'}), 400
    charge = calculate_charge(volume, data['destination'])
    consignment = Consignment(
        volume=volume,
        destination=data['destination'],
        sender_name=data['sender_name'],
        sender_address=data['sender_address'],
        receiver_name=data['receiver_name'],
        receiver_address=data['receiver_address'],
        charge=charge,
        branch_id=branch_id
    )
    db.session.add(consignment)
    db.session.commit()
    truck, consignments = check_truck_allocation(data['destination'], branch_id)
    if truck:
        return jsonify({
            'message': 'Consignment added and truck allocated automatically',
            'truck_id': truck.id,
            'consignments': [{'id': c.id, 'volume': c.volume} for c in consignments]
        }), 201
    return jsonify({'message': 'Consignment added'}), 201

@app.route('/consignments', methods=['GET'])
def get_consignments():
    user = db.session.get(User, session['user_id'])
    query = Consignment.query
    if user.role == 'Employee':
        query = query.filter_by(branch_id=user.branch_id)
    consignments = query.all()
    return jsonify([{
        'id': c.id,
        'volume': c.volume,
        'destination': c.destination,
        'status': c.status,
        'charge': c.charge,
        'created_at': c.created_at.isoformat(),
        'branch_id': c.branch_id
    } for c in consignments])

@app.route('/consignments/<id>', methods=['GET'])
def get_consignment(id):
    consignment = db.session.get(Consignment, id)
    if not consignment:
        return jsonify({'error': 'Consignment not found'}), 404
    user = db.session.get(User, session['user_id'])
    if user.role == 'Employee' and consignment.branch_id != user.branch_id:
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify({
        'id': consignment.id,
        'volume': consignment.volume,
        'destination': consignment.destination,
        'status': consignment.status,
        'charge': consignment.charge
    })

@app.route('/consignments/assign', methods=['POST'])
def assign_consignment():
    data = request.json
    consignment_id = data.get('consignment_id')
    truck_id = data.get('truck_id')
    if not consignment_id or not truck_id:
        return jsonify({'error': 'Consignment ID and Truck ID required'}), 400
    consignment = db.session.get(Consignment, consignment_id)
    truck = db.session.get(Truck, truck_id)
    if not consignment or not truck:
        return jsonify({'error': 'Invalid consignment or truck ID'}), 404
    if consignment.status != 'Pending':
        return jsonify({'error': 'Consignment must be in Pending status'}), 400
    if consignment.branch_id != truck.branch_id:
        return jsonify({'error': 'Consignment and truck must be in the same branch'}), 400
    current_volume = get_truck_volume(truck_id)
    if current_volume + consignment.volume > 500:
        return jsonify({'error': 'Assigning this consignment would exceed truck capacity (500 cubic meters)'}), 400
    consignment.status = 'Dispatched'
    consignment.dispatched_at = datetime.now(IST)
    truck.status = 'In-Transit'
    truck.last_updated = datetime.now(IST)
    db.session.add(ConsignmentTruck(consignment_id=consignment_id, truck_id=truck_id))
    db.session.commit()
    return jsonify({'message': 'Consignment assigned to truck successfully'}), 201

@app.route('/trucks', methods=['GET'])
def get_trucks():
    user = db.session.get(User, session['user_id'])
    query = Truck.query
    if user.role == 'Employee':
        query = query.filter_by(branch_id=user.branch_id)
    trucks = query.all()
    truck_data = []
    for truck in trucks:
        consignments = Consignment.query.join(ConsignmentTruck).filter(
            ConsignmentTruck.truck_id == truck.id
        ).all()
        truck_data.append({
            'id': truck.id,
            'location': truck.location,
            'status': truck.status,
            'last_updated': truck.last_updated.isoformat(),
            'volume': get_truck_volume(truck.id),
            'consignments': [{'id': c.id, 'volume': c.volume, 'destination': c.destination} for c in consignments],
            'branch_id': truck.branch_id
        })
    return jsonify(truck_data)

@app.route('/trucks', methods=['POST'])
def add_truck():
    data = request.json
    if not data.get('location') or not data.get('branch_id'):
        return jsonify({'error': 'Location and branch_id required'}), 400
    if not db.session.get(Branch, data['branch_id']):
        return jsonify({'error': 'Invalid branch_id'}), 400
    truck = Truck(
        location=data['location'],
        branch_id=data['branch_id']
    )
    db.session.add(truck)
    db.session.commit()
    return jsonify({'message': 'Truck added successfully', 'truck_id': truck.id}), 201

@app.route('/trucks/assign', methods=['POST'])
def assign_truck():
    data = request.get_json()

    truck_id = data.get('truck_id')
    
    

    if not truck_id:
        return jsonify({'error': 'Truck ID and Driver ID required'}), 400

    truck = db.session.get(Truck, truck_id)


    if not truck:
        return jsonify({'error': 'Invalid truck or driver ID'}), 404

    # if driver.role != 'Driver':
    #     return jsonify({'error': 'Selected user is not a driver'}), 400

    # Branch check
    # if truck.branch_id != driver.branch_id:
    #     return jsonify({'error': 'Truck and driver must be in the same branch'}), 400

    # Assign
    # assignment = TruckAssignment(truck_id=truck_id, driver_id=driver_id)
    # db.session.add(assignment)
    db.session.commit()

    return jsonify({'message': 'Truck assigned to driver successfully'}), 201

@app.route('/trucks/assigned', methods=['GET'])
def get_assigned_trucks():
    user = db.session.get(User, session['user_id'])
    assignments = TruckAssignment.query.filter_by(employee_id=user.id).all()
    trucks = []
    for assignment in assignments:
        truck = db.session.get(Truck, assignment.truck_id)
        if truck:
            trucks.append({
                'id': truck.id,
                'location': truck.location,
                'status': truck.status,
                'volume': get_truck_volume(truck.id),
                'assigned_at': assignment.assigned_at.isoformat()
            })
    return jsonify(trucks)

@app.route('/reports/usage', methods=['GET'])
def truck_usage():
    days = int(request.args.get('days', 30))
    start_date = datetime.now(IST) - timedelta(days=days)
    trucks = Truck.query.all()
    usage = []
    for truck in trucks:
        consignments = Consignment.query.join(ConsignmentTruck).filter(
            ConsignmentTruck.truck_id == truck.id,
            Consignment.dispatched_at >= start_date
        ).all()
        usage.append({
            'truck_id': truck.id,
            'consignments_handled': len(consignments),
            'total_volume': sum(c.volume for c in consignments)
        })
    return jsonify(usage)

@app.route('/reports/consignments', methods=['GET'])
def consignment_report():
    destination = request.args.get('destination')
    query = Consignment.query
    if destination:
        query = query.filter_by(destination=destination)
    consignments = query.all()
    return jsonify({
        'total_volume': sum(c.volume for c in consignments),
        'total_revenue': sum(c.charge for c in consignments),
        'count': len(consignments)
    })

@app.route('/reports/waiting', methods=['GET'])
def waiting_report():
    consignments = Consignment.query.filter(Consignment.status == 'Dispatched').all()
    waiting_times = [
        (c.dispatched_at - c.created_at).total_seconds() / 3600
        for c in consignments if c.dispatched_at
    ]
    avg_waiting = sum(waiting_times) / len(waiting_times) if waiting_times else 0
    trucks = Truck.query.filter_by(status='Available').all()
    idle_times = [
        (datetime.now(IST) - t.last_updated).total_seconds() / 3600
        for t in trucks
    ]
    avg_idle = sum(idle_times) / len(idle_times) if idle_times else 0
    return jsonify({
        'avg_waiting_time_hours': avg_waiting,
        'avg_idle_time_hours': avg_idle
    })

@app.route('/employees', methods=['POST'])
def add_employee():
    data = request.json
    if not data.get('username') or not data.get('password') or not data.get('branch_id'):
        return jsonify({'error': 'Username, password, and branch_id required'}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    if not db.session.get(Branch, data['branch_id']):
        return jsonify({'error': 'Invalid branch_id'}), 400
    hashed_pwd = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    employee = User(
        username=data['username'],
        password=hashed_pwd.decode('utf-8'),
        role='Employee',
        branch_id=data['branch_id']
    )
    db.session.add(employee)
    db.session.commit()
    return jsonify({'message': 'Employee added successfully'}), 201

@app.route('/employees', methods=['GET'])
def get_employees():
    user = db.session.get(User, session['user_id'])
    query = User.query
    if user.role == 'Employee':
        query = query.filter_by(branch_id=user.branch_id)
    employees = query.all()
    return jsonify([{
        'id': e.id,
        'username': e.username,
        'role': e.role,
        'branch_id': e.branch_id
    } for e in employees])

@app.route('/branches', methods=['POST'])
def add_branch():
    data = request.json
    if not data.get('location'):
        return jsonify({'error': 'Location required'}), 400
    if Branch.query.filter_by(location=data['location']).first():
        return jsonify({'error': 'Branch location already exists'}), 400
    branch = Branch(id=data['branchId'], location=data['location'])
    db.session.add(branch)
    db.session.commit()
    return jsonify({'message': 'Branch added successfully', 'branch_id': branch.id}), 201


@app.route('/customer/logout')
def customer_logout():
    session.pop('customer_id', None)
    return redirect(url_for('login'))

# -------- Customer routes (safe + working) --------
@app.route('/customer/dashboard')
@login_required(role='Customer')
def customer_dashboard():
    user = db.session.get(User, session.get('user_id'))
    if not user:
        return redirect(url_for('login'))

    # find customer based on username (email)
    cust = Customer.query.filter_by(email=user.username).first()
    if not cust:
        cust = Customer(
            name=user.username.split('@')[0],
            email=user.username,
            password=user.password,
            phone='',
            address=''
        )
        db.session.add(cust)
        db.session.commit()

    consignments = Consignment.query.filter_by(sender_name=cust.name).all()
    return render_template('customer_dashboard.html', customer=cust, consignments=consignments)


@app.route('/customer/consignments', methods=['POST'])
@login_required(role='Customer')
def customer_add_consignment():
    # Accept JSON OR form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    user = db.session.get(User, session.get('user_id'))
    cust = Customer.query.filter_by(email=user.username).first()

    branch_id = data.get('branch_id')
    if not branch_id:
        flash("branch_id required", "error")
        return redirect(url_for('customer_dashboard'))

    try:
        volume = float(data.get('volume'))
        if volume > 500.0:
            raise ValueError("Volume cannot exceed 500.0")
    except:
        flash("Invalid volume", "error")
        return redirect(url_for('customer_dashboard'))

    destination = data.get('destination')
    receiver_name = data.get('receiver_name')
    receiver_address = data.get('receiver_address')

    charge = calculate_charge(volume, destination)

    cons = Consignment(
        volume=volume,
        destination=destination,
        sender_name=cust.name,
        sender_address=cust.address or '',
        receiver_name=receiver_name,
        receiver_address=receiver_address,
        charge=charge,
        branch_id=branch_id
    )

    db.session.add(cons)
    db.session.commit()

    truck, consignments = check_truck_allocation(destination, branch_id)
    if truck:
        flash("Consignment added and truck allocated!", "success")
        return redirect(url_for('customer_dashboard'))


    flash("Consignment added successfully!", "success")
    return redirect(url_for('customer_dashboard'))



@app.route('/customer/consignments', methods=['GET'])
@login_required(role='Customer')
def customer_get_consignments():
    user = db.session.get(User, session.get('user_id'))
    cust = Customer.query.filter_by(email=user.username).first()

    consignments = Consignment.query.filter_by(sender_name=cust.name).all()

    return jsonify([
        {'id': c.id, 'volume': c.volume, 'status': c.status, 'destination': c.destination}
        for c in consignments
    ])

@app.route('/customer/consignments/delete/<cid>', methods=['POST'])
@login_required(role='Customer')
def customer_delete_consignment(cid):
    user = db.session.get(User, session['user_id'])
    cust = Customer.query.filter_by(email=user.username).first()

    c = Consignment.query.filter_by(id=cid, sender_name=cust.name).first()
    if not c:
        return "Not found", 404

    if c.status != "Pending":
        return "Cannot delete dispatched consignment", 400

    db.session.delete(c)
    db.session.commit()
    return redirect(url_for('customer_dashboard'))

@app.route('/customer/consignments/update/<cid>', methods=['POST'])
@login_required(role='Customer')
def customer_update_consignment(cid):
    user = db.session.get(User, session['user_id'])
    cust = Customer.query.filter_by(email=user.username).first()

    c = Consignment.query.filter_by(id=cid, sender_name=cust.name).first()
    if not c:
        return "Not found", 404

    if c.status != "Pending":
        return "Cannot update dispatched consignment", 400

    form = request.form
    c.volume = float(form.get("volume", c.volume))
    c.destination = form.get("destination", c.destination)
    c.receiver_name = form.get("receiver_name", c.receiver_name)
    c.receiver_address = form.get("receiver_address", c.receiver_address)

    db.session.commit()
    return redirect(url_for('customer_dashboard'))



@app.route('/customer/consignments/invoice/<cid>')
@login_required(role='Customer')
def customer_invoice(cid):
    user = db.session.get(User, session['user_id'])
    cust = Customer.query.filter_by(email=user.username).first()

    c = Consignment.query.filter_by(id=cid, sender_name=cust.name).first()
    if not c:
        return "Not found", 404

    pdf_file = f"invoice_{cid}.pdf"
    pdf = canvas.Canvas(pdf_file, pagesize=letter)

    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(200, 750, "TCCS Invoice")

    pdf.setFont("Helvetica", 12)
    pdf.drawString(50, 700, f"Invoice for: {cust.name}")
    pdf.drawString(50, 680, f"Email: {cust.email}")
    pdf.drawString(50, 660, f"Consignment ID: {cid}")

    pdf.drawString(50, 630, f"Destination: {c.destination}")
    pdf.drawString(50, 610, f"Volume: {c.volume} m³")
    pdf.drawString(50, 590, f"Status: {c.status}")
    pdf.drawString(50, 570, f"Charge: ₹{c.charge}")

    pdf.save()
    return send_file(pdf_file, as_attachment=True)

# driver dashboard: show assigned trucks and consignments
@app.route('/driver/dashboard')
@login_required(role='Driver')
def driver_dashboard():
    user = db.session.get(User, session['user_id'])
    
    if not user:
        return redirect(url_for('login'))

    # use employee_id (table/model field) to find assignments for this user
    assignments = TruckAssignment.query.filter_by(driver_id=user.id).all()
    trucks = []
    print(assignments)
    for a in assignments:
        truck = db.session.get(Truck, a.truck_id)
        if truck:
            # you may want to include consignment details for assigned truck
            consignments = Consignment.query.join(ConsignmentTruck).filter(
                ConsignmentTruck.truck_id == truck.id
            ).all()
            trucks.append({
                'truck': truck,
                'consignments': consignments,
                'assigned_at': a.assigned_at
            })
    return render_template('driver_dashboard.html', user=user, trucks=trucks)


@app.route('/driver/consignment/update/<cid>', methods=['POST'])
@login_required(role='Driver')
def driver_update_status(cid):
    user = db.session.get(User, session['user_id'])

    assignment = TruckAssignment.query.filter_by(employee_id=user.id).first()
    if not assignment:
        return "Not allowed", 403

    cons = Consignment.query.join(ConsignmentTruck).filter(
        ConsignmentTruck.truck_id == assignment.truck_id,
        Consignment.id == cid
    ).first()

    if not cons:
        return "Consignment not found", 404

    new_status = request.form['status']
    cons.status = new_status
    db.session.commit()

    return redirect(url_for('driver_dashboard'))


# change truck status (Driver action)
@app.route('/driver/truck/<tid>/status', methods=['POST'])
@login_required(role='Driver')
def driver_change_truck_status(tid):
    user = db.session.get(User, session['user_id'])
    # ensure truck is assigned to this driver
    assign = TruckAssignment.query.filter_by(truck_id=tid, employee_id=user.id).first()
    if not assign:
        flash("Unauthorized or truck not assigned to you", "error")
        return redirect(url_for('driver_dashboard'))

    new_status = request.form.get('status')
    if new_status not in ('Available','In-Transit'):
        flash("Invalid truck status", "error")
        return redirect(url_for('driver_dashboard'))

    truck = db.session.get(Truck, tid)
    if not truck:
        flash("Truck not found", "error")
        return redirect(url_for('driver_dashboard'))

    truck.status = new_status
    truck.last_updated = datetime.now(IST)
    db.session.commit()
    flash(f"Truck status set to {new_status}", "success")
    return redirect(url_for('driver_dashboard'))

# change consignment status (Driver action)
@app.route('/driver/consignment/<cid>/status', methods=['POST'])
@login_required(role='Driver')
def driver_change_consignment_status(cid):
    user = db.session.get(User, session['user_id'])
    # only allow action if consignment assigned to any truck assigned to this driver
    assigned_truck_ids = [a.truck_id for a in TruckAssignment.query.filter_by(employee_id=user.id).all()]
    consignment_truck = ConsignmentTruck.query.filter_by(consignment_id=cid).first()
    if not consignment_truck or consignment_truck.truck_id not in assigned_truck_ids:
        flash("Consignment not assigned to your trucks", "error")
        return redirect(url_for('driver_dashboard'))

    c = db.session.get(Consignment, cid)
    if not c:
        flash("Consignment not found", "error")
        return redirect(url_for('driver_dashboard'))

    new_status = request.form.get('status')
    if new_status not in ('In-Transit','Delivered'):
        flash("Invalid status", "error")
        return redirect(url_for('driver_dashboard'))

    # update status and timestamps
    c.status = new_status
    if new_status == 'In-Transit':
        c.dispatched_at = datetime.now(IST)
    elif new_status == 'Delivered':
        c.dispatched_at = c.dispatched_at or datetime.now(IST)

    db.session.commit()
    flash(f"Consignment {new_status}", "success")
    return redirect(url_for('driver_dashboard'))


@app.route('/drivers', methods=['POST'])
def add_driver_user():
    data = request.json
    if not data.get('username') or not data.get('password') or not data.get('branch_id'):
        return jsonify({'error':'username,password,branch required'}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error':'Username exists'}), 400
    hashed = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode()
    d = User(username=data['username'], password=hashed, role='Driver', branch_id=data['branch_id'])
    db.session.add(d); db.session.commit()
    return jsonify({'message':'Driver user added','id':d.id}), 201

@app.route('/drivers', methods=['GET'])
def get_drivers():
    user = db.session.get(User, session['user_id'])
    query = User.query
    if user.role == 'Driver':
        query = query.filter_by(branch_id=user.branch_id)
    drivers = query.all()
    return jsonify([{
        'id': e.id,
        'username': e.username,
        'role': e.role,
        'branch_id': e.branch_id
    } for e in drivers])

@app.route('/dashboard')
def dashboard():
    user = db.session.get(User, session['user_id'])
    if user.role == 'Manager':
        branches = Branch.query.all()
        return render_template('manager_dashboard.html', branches=branches)
    if user.role == 'Driver':
        return redirect(url_for('driver_dashboard'))
    if user.role == 'Customer':
        return redirect(url_for('customer_dashboard'))
    return render_template('employee_dashboard.html', branch_id=user.branch_id)

# Initialize Database
with app.app_context():
    # db.drop_all()
    db.create_all()
    if not Branch.query.first():
        branches = ['Capital', 'CityA', 'CityB']
        for loc in branches:
            branch = Branch(location=loc)
            db.session.add(branch)
            db.session.commit()
            for _ in range(2):
                db.session.add(Truck(location=loc, branch_id=branch.id))
        db.session.commit()
    if not User.query.first():
        hashed_pwd = bcrypt.hashpw('managerpass'.encode('utf-8'), bcrypt.gensalt())
        db.session.add(User(username='manager1', password=hashed_pwd.decode('utf-8'), role='Manager'))
        branch = Branch.query.filter_by(location='CityA').first()
        hashed_pwd = bcrypt.hashpw('employeepass'.encode('utf-8'), bcrypt.gensalt())
        db.session.add(User(username='employee1', password=hashed_pwd.decode('utf-8'), role='Employee', branch_id=branch.id))
        db.session.commit()

# ------- debug helper: who am i? -------
@app.route('/_whoami')
def whoami():
    return jsonify({
        'session_keys': list(session.keys()),
        'user_id_in_session': session.get('user_id'),
        'user': (lambda u: {'id':u.id,'username':u.username,'role':u.role} if u else None)(db.session.get(User, session.get('user_id')))
    })


if __name__ == '__main__':
    app.run(debug=True)
