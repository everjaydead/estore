from flask import Flask, render_template, redirect, url_for, session, request, flash
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Define the absolute path to the database
DATABASE_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'joone.db')

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_secret_key')  # Ensure your secret key is set for session management
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'  # Define the database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy for ORM
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
    """Fetch all products from the database"""
    products = Product.query.all()
    return {str(product.id): {'name': product.name, 'price': product.price, 'image': product.image, 'year': product.year} for product in products}

@app.route('/')
def index():
    """Render the homepage with a list of products"""
    products = fetch_products()
    return render_template('index.html', products=products, logged_in=session.get('user_id'), is_admin=session.get('is_admin'))

@app.route('/product/<id>')
def view_product(id):
    """Render a page to view a specific product"""
    product = Product.query.get(id)
    if product:
        image_path = url_for('static', filename=product.image)
        return render_template('product.html', product=product, image_url=image_path)
    return "Product not found", 404

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
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

        is_first_user_admin = User.query.filter_by(is_admin=True).count() == 0
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
    """Handle user login"""
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
    """Log out the user"""
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('Logged out successfully!')
    return redirect(url_for('index'))

@app.route('/add_to_cart/<id>')
def add_to_cart(id):
    """Add a product to the shopping cart"""
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
    """Show the contents of the shopping cart"""
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

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    """Allow admins to add a new product"""
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

@app.route('/manage_products')
def manage_products():
    """List and manage all products (admin only)"""
    if not session.get('is_admin'):
        flash('You do not have permission to manage products.')
        return redirect(url_for('index'))
    
    products = fetch_products()
    return render_template('manage_products.html', products=products)

@app.route('/edit_product/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    """Edit a specific product"""
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
    """Update user profile information"""
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
    """View the logged-in user's order history"""
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

@app.route('/admin_dashboard')
def admin_dashboard():
    """Dashboard view for admins"""
    if not session.get('is_admin'):
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    
    return render_template('admin_dashboard.html')

@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    """Manage user roles and access (admin only)"""
    if not session.get('is_admin'):
        flash('You do not have permission to manage users.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        user_id = request.form['user_id']
        action = request.form['action']
        user = User.query.get(user_id)

        if user:
            if action == 'promote':
                user.is_admin = True
            elif action == 'demote':
                user.is_admin = False
            elif action == 'delete':
                db.session.delete(user)
            db.session.commit()
            flash(f'User {action}d successfully.')
        else:
            flash('User not found.')

    users_list = User.query.all()
    return render_template('manage_users.html', users=users_list)

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    """Edit a user's information (admin only)"""
    if not session.get('is_admin'):
        flash('You do not have permission to manage users.')
        return redirect(url_for('index'))

    user = User.query.get(id)
    if request.method == 'POST':
        new_username = request.form['username']
        if user:
            user.username = new_username
            db.session.commit()
            flash('User information updated successfully!')
            return redirect(url_for('manage_users'))
    return render_template('edit_user.html', user=user)

@app.route('/change_admin_password', methods=['GET', 'POST'])
def change_admin_password():
    """Allows admin users to change their passwords"""
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

# Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)