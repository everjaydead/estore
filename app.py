from flask import Flask, render_template, redirect, url_for, session, request, flash
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_secret_key')  # Use environment variable for production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///joone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200), nullable=False)
    year = db.Column(db.Integer, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)

# Helper Functions
def fetch_products():
    products = Product.query.all()
    return {str(product.id): {'name': product.name, 'price': product.price, 'image': product.image, 'year': product.year} for product in products}

@app.route('/')
def index():
    products = fetch_products()
    year = request.args.get('year', default=2020, type=int)
    current_year = datetime.now().year
    return render_template('index.html', products=products, year=year, current_year=current_year, logged_in=session.get('user_id'), is_admin=session.get('is_admin'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or not confirm_password:
            flash('Please fill in all fields.')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))

        # Check if any admin exists
        is_first_user_admin = User.query.filter_by(is_admin=True).count() == 0

        # Create new user with admin rights if the first
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, is_admin=is_first_user_admin)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except Exception as e:
            print(e)
            db.session.rollback()
            flash('An error occurred during registration.')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Login successful!')
            return redirect(url_for('index'))

        flash('Invalid username or password.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('Logged out successfully!')
    return redirect(url_for('index'))

@app.route('/add_to_cart/<id>')
def add_to_cart(id):
    if not session.get('user_id'):
        flash("You must be logged in to add items to your cart.")
        return redirect(url_for('login'))

    if 'cart' not in session:
        session['cart'] = {}
    cart = session['cart']
    cart[id] = cart.get(id, 0) + 1
    session['cart'] = cart
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    cart = session.get('cart', {})
    cart_items = []
    total_price = 0
    for id, quantity in cart.items():
        product = fetch_products().get(id)
        if product:
            item_total = product['price'] * quantity
            cart_items.append({
                'id': id,
                'name': product['name'],
                'price': product['price'],
                'quantity': quantity,
                'total': item_total
            })
            total_price += item_total
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)

@app.route('/product/<id>')
def product(id):
    product = Product.query.get(id)
    if product:
        image_path = url_for('static', filename=product.image)
        return render_template('product.html', product=product, id=id)
    return "Product not found", 404

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if not session.get('user_id'):
        flash('You must be logged in to add products.')
        return redirect(url_for('login'))

    if not session.get('is_admin'):
        flash('You do not have permission to add products.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        image = request.form['image']
        year = request.form['year']

        if image.startswith('static/'):
            image = image[7:]

        if not name or not price or not image or not year:
            flash('Please fill in all fields.')
            return redirect(url_for('add_product'))

        try:
            new_product = Product(name=name, price=float(price), image=image, year=int(year))
            db.session.add(new_product)
            db.session.commit()
            flash('Product added successfully!')
            return redirect(url_for('index'))
        except Exception as e:
            print(e)
            db.session.rollback()
            flash('An error occurred while adding the product.')
            return redirect(url_for('add_product'))

    return render_template('add_product.html')

@app.route('/manage_products', methods=['GET'])
def manage_products():
    if not session.get('is_admin'):
        flash('You do not have permission to manage products.')
        return redirect(url_for('index'))
    
    products = fetch_products()
    return render_template('manage_products.html', products=products)

@app.route('/edit_product/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    if not session.get('user_id'):
        flash('You must be logged in to edit products.')
        return redirect(url_for('login'))

    if not session.get('is_admin'):
        flash('You do not have permission to edit products.')
        return redirect(url_for('index'))

    product = Product.query.get(id)
    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        image = request.form['image']
        year = request.form['year']

        if image.startswith('static/'):
            image = image[7:]

        if not name or not price or not image or not year:
            flash('Please fill in all fields.')
            return redirect(url_for('edit_product', id=id))

        try:
            product.name = name
            product.price = float(price)
            product.image = image
            product.year = int(year)
            db.session.commit()
            flash('Product details updated successfully!')
            return redirect(url_for('manage_products'))
        except Exception as e:
            print(e)
            db.session.rollback()
            flash('An error occurred while updating the product.')
            return redirect(url_for('edit_product', id=id))
    else:
        if product:
            return render_template('edit_product.html', product=product)
        else:
            flash('Product not found.')
            return redirect(url_for('manage_products'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to access your profile.')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password and new_password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('profile'))

        try:
            user.username = username
            if new_password:
                user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Profile updated successfully!')
            return redirect(url_for('profile'))
        except Exception as e:
            print(e)
            db.session.rollback()
            flash('An error occurred while updating the profile.')
            return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/order_history')
def order_history():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view your order history.')
        return redirect(url_for('login'))

    user_orders = Order.query.filter_by(user_id=user_id).all()
    orders = [{
        'id': order.id,
        'product_name': Product.query.get(order.product_id).name,
        'quantity': order.quantity,
        'order_date': order.order_date
    } for order in user_orders]

    return render_template('order_history.html', orders=orders)

@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    if not session.get('is_admin'):
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    
    return render_template('admin_dashboard.html')

@app.route('/users', methods=['GET', 'POST'])
def users():
    if not session.get('is_admin'):
        flash('You do not have permission to manage users.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        user_id = request.form['user_id']
        is_admin = request.form['is_admin'] == 'True'
        user = User.query.get(user_id)
        user.is_admin = is_admin
        db.session.commit()
        flash('User updated successfully.')

    users_list = User.query.all()
    return render_template('users.html', users=users_list)

@app.route('/change_admin_password', methods=['GET', 'POST'])
def change_admin_password():
    if not session.get('is_admin'):
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password and new_password != confirm_password:
            flash('New passwords do not match.')
            return redirect(url_for('change_admin_password'))

        admin_user = User.query.get(session['user_id'])

        if admin_user and check_password_hash(admin_user.password, current_password):
            admin_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Password changed successfully!')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Current password is incorrect.')
            return redirect(url_for('change_admin_password'))

    return render_template('change_admin_password.html')

if __name__ == '__main__':
    app.run(debug=True)