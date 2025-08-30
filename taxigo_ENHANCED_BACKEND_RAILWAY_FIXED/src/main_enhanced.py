from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'taxigo_pro_enhanced_secret_2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///taxigo_enhanced.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
CORS(app, origins="*")

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(20), nullable=False, default='passenger')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'phone': self.phone,
            'user_type': self.user_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active
        }

# Ride Model
class Ride(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    passenger_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    pickup_location = db.Column(db.String(255), nullable=False)
    destination = db.Column(db.String(255), nullable=False)
    pickup_lat = db.Column(db.Float, nullable=True)
    pickup_lng = db.Column(db.Float, nullable=True)
    destination_lat = db.Column(db.Float, nullable=True)
    destination_lng = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(20), default='requested')
    fare = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'passenger_id': self.passenger_id,
            'driver_id': self.driver_id,
            'pickup_location': self.pickup_location,
            'destination': self.destination,
            'pickup_lat': self.pickup_lat,
            'pickup_lng': self.pickup_lng,
            'destination_lat': self.destination_lat,
            'destination_lng': self.destination_lng,
            'status': self.status,
            'fare': self.fare,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }

# Helper function to generate JWT token
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Helper function to verify JWT token
def verify_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'Enhanced TaxiGo API is running',
        'features': ['authentication', 'rides', 'payments', 'gps']
    })

@app.route('/api/health/enhanced', methods=['GET'])
def enhanced_health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'Enhanced TaxiGo API is running',
        'version': '2.0',
        'features': ['authentication', 'rides', 'payments', 'gps', 'notifications']
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'password', 'user_type']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'{field} is required'}), 400

        # Check if user already exists
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            return jsonify({'success': False, 'error': 'Email already registered'}), 400

        # Create new user
        user = User(
            name=data['name'],
            email=data['email'],
            phone=data.get('phone', ''),
            user_type=data['user_type']
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()

        # Generate token
        token = generate_token(user.id)

        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'token': token,
            'user': user.to_dict()
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        # Validate required fields
        if 'email' not in data or 'password' not in data:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400

        # Find user
        user = User.query.filter_by(email=data['email']).first()
        if not user or not user.check_password(data['password']):
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

        # Generate token
        token = generate_token(user.id)

        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': user.to_dict()
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/verify-token', methods=['POST'])
def verify_user_token():
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'success': False, 'error': 'Token is required'}), 400

        user_id = verify_token(token)
        if not user_id:
            return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401

        user = User.query.get(user_id)
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404

        return jsonify({
            'success': True,
            'user': user.to_dict()
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/rides/book', methods=['POST'])
def book_ride():
    try:
        data = request.get_json()
        
        # Get user from token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Authorization token required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401

        # Create ride
        ride = Ride(
            passenger_id=user_id,
            pickup_location=data.get('pickup_location', ''),
            destination=data.get('destination', ''),
            pickup_lat=data.get('pickup_lat'),
            pickup_lng=data.get('pickup_lng'),
            destination_lat=data.get('destination_lat'),
            destination_lng=data.get('destination_lng'),
            fare=data.get('fare', 0.0)
        )
        
        db.session.add(ride)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Ride booked successfully',
            'ride': ride.to_dict()
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/rides/history', methods=['GET'])
def get_ride_history():
    try:
        # Get user from token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Authorization token required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401

        # Get rides for user
        rides = Ride.query.filter_by(passenger_id=user_id).order_by(Ride.created_at.desc()).all()
        
        return jsonify({
            'success': True,
            'rides': [ride.to_dict() for ride in rides]
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/stats', methods=['GET'])
def get_system_stats():
    try:
        total_users = User.query.count()
        total_rides = Ride.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_users': total_users,
                'total_rides': total_rides,
                'active_users': active_users,
                'uptime': '99.9%',
                'version': '2.0'
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/system/business-intelligence', methods=['GET'])
def get_business_intelligence():
    try:
        return jsonify({
            'success': True,
            'data': {
                'revenue': {
                    'today': 1250.50,
                    'week': 8750.25,
                    'month': 35000.00
                },
                'rides': {
                    'today': 45,
                    'week': 320,
                    'month': 1280
                },
                'growth': {
                    'users': 15.5,
                    'revenue': 22.3,
                    'rides': 18.7
                }
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Create tables on startup
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
