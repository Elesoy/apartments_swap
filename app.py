from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from data.districts import districts, areas

app = Flask(__name__)
app.secret_key = 'секретный_ключ'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/database.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
db = SQLAlchemy(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))

class Listing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    district = db.Column(db.String(100))
    area = db.Column(db.String(100))
    address = db.Column(db.String(200))
    rooms = db.Column(db.Integer)
    size = db.Column(db.Float)
    exchange_type = db.Column(db.String(100))
    description = db.Column(db.Text)
    contact = db.Column(db.String(150))
    photo = db.Column(db.String(300))
    user = db.relationship('User', backref='listings')

@app.route('/')
def index():
    selected_district = request.args.get('district')
    selected_exchange_type = request.args.get('exchange_type')
    query = Listing.query
    if selected_district:
        query = query.filter_by(district=selected_district)
    if selected_exchange_type:
        query = query.filter_by(exchange_type=selected_exchange_type)
    listings = query.all()
    return render_template('index.html', listings=listings, districts=districts,
                           selected_district=selected_district,
                           selected_exchange_type=selected_exchange_type)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form['password'])
        user = User(name=request.form['name'], email=request.form['email'], password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/add', methods=['GET', 'POST'])
def add_listing():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        photo_path = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                photo_path = f'/static/uploads/{filename}'

        listing = Listing(
            user_id=session['user_id'],
            district=request.form['district'],
            area=request.form['area'],
            address=request.form['address'],
            rooms=int(request.form['rooms']),
            size=float(request.form['size']),
            exchange_type=request.form['exchange_type'],
            description=request.form['description'],
            contact=request.form['contact'],
            photo=photo_path
        )
        db.session.add(listing)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('add_listing.html', districts=districts, areas=areas)

@app.route('/listing/<int:listing_id>')
def view_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    return render_template('view_listing.html', listing=listing)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
