from flask import Flask, render_template, redirect, url_for, session, request, flash
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Define the path to the database
DATABASE_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'joone.db')

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy for ORM
db = SQLAlchemy(app)

# Define Models
wishlist_items = db.Table('wishlist_items',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('product_id', db.Integer, db.ForeignKey('product.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    wishlist = db.relationship('Product', secondary=wishlist_items, back_populates='wishlisted_by')
    reviews = db.relationship('Review', cascade='all,delete-orphan', back_populates='user')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    wishlisted_by = db.relationship('User', secondary=wishlist_items, back_populates='wishlist')
    reviews = db.relationship('Review', order_by='Review.id', back_populates='product')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    review_date = db.Column(db.DateTime, default=datetime.utcnow)
    product = db.relationship('Product', back_populates='reviews')
    user = db.relationship('User', back_populates='reviews')

class SavedForLater(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    date_saved = db.Column(db.DateTime, default=datetime.utcnow)

# Context processor to add current year globally
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

# Routes
@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products, logged_in=session.get('user_id'), is_admin=session.get('is_admin'))

@app.route('/product/<int:id>')
def view_product(id):
    product = Product.query.get(id)
    if product:
        image_path = url_for('static', filename=product.image)
        return render_template('product.html', product=product, image_url=image_path)
    flash('Product not found.')
    return redirect(url_for('index'))

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
    session.clear()  # Clears all session data
    flash('Logged out successfully!')
    return redirect(url_for('index'))

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    """Add a product to the shopping cart"""
    if not session.get('user_id'):
        flash("You must be logged in to add items to your cart.")
        return redirect(url_for('login'))

    session.setdefault('cart', {})
    cart = session['cart']
    cart[product_id] = cart.get(product_id, 0) + 1  # Increment product count in cart
    session.modified = True  # Flag session as modified to update cookie
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view your cart.')
        return redirect(url_for('login'))

    cart = session.get('cart', {})
    cart_items = []
    total_price = 0
    for product_id, quantity in cart.items():
        product = Product.query.get(product_id)
        if product:
            item_total = product.price * quantity
            cart_items.append({'product': product, 'quantity': quantity, 'total': item_total})
            total_price += item_total

    saved_items = SavedForLater.query.filter_by(user_id=user_id).all()
    recommendations = []
    if cart_items:
        product_ids = [item['product'].id for item in cart_items]
        recommendations = Product.query.filter(Product.id.notin_(product_ids)).limit(3).all()

    return render_template('cart.html', cart_items=cart_items, saved_items=saved_items, total_price=total_price, recommendations=recommendations)

@app.route('/save_for_later/<int:product_id>', methods=['POST'])
def save_for_later(product_id):
    if not session.get('user_id'):
        flash('Log in to save this item for later.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    saved_item = SavedForLater.query.filter_by(user_id=user_id, product_id=product_id).first()

    if not saved_item:
        new_saved_item = SavedForLater(user_id=user_id, product_id=product_id)
        db.session.add(new_saved_item)
        db.session.commit()
        flash('Item saved for later.')
    else:
        flash('Item is already saved for later.')

    return redirect(url_for('cart'))

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
            return redirect(url_for('manage_products'))
        except Exception as e:
            print(e)
            db.session.rollback()
            flash('An error occurred while adding the product.')
            return redirect(url_for('add_product'))

    return render_template('add_product.html')

@app.route('/manage_products')
def manage_products():
    if not session.get('is_admin'):
        flash('You do not have permission to manage products.')
        return redirect(url_for('index'))
    
    products = Product.query.all()
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
    if product and request.method == 'POST':
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
    elif not product:
        flash('Product not found.')
        return redirect(url_for('manage_products'))

    return render_template('edit_product.html', product=product)

@app.route('/delete_product/<int:id>', methods=['POST'])
def delete_product(id):
    if not session.get('is_admin'):
        flash('You do not have permission to delete products.')
        return redirect(url_for('index'))

    product = Product.query.get(id)
    if product:
        try:
            db.session.delete(product)
            db.session.commit()
            flash('Product successfully deleted.')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while deleting the product.')
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

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    
    admin_data = {
        'total_users': User.query.count(),
        'total_products': Product.query.count(),
        'recent_orders': Order.query.order_by(Order.order_date.desc()).limit(10).all()
    }
    return render_template('admin_dashboard.html', admin_data=admin_data)

@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
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

@app.route('/users', methods=['GET'])
def users():
    if not session.get('is_admin'):
        flash('You do not have permission to access the users list.')
        return redirect(url_for('index'))
    
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

@app.route('/add_review/<int:product_id>', methods=['POST'])
def add_review(product_id):
    if not session.get('user_id'):
        flash('You must be logged in to leave a review.')
        return redirect(url_for('login'))

    rating = int(request.form['rating'])
    comment = request.form.get('comment')
    review = Review(user_id=session['user_id'], product_id=product_id, rating=rating, comment=comment)

    try:
        db.session.add(review)
        db.session.commit()
        flash('Review added successfully!')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while adding your review.')

    return redirect(url_for('view_product', id=product_id))

@app.route('/add_to_wishlist/<int:product_id>', methods=['POST'])
def add_to_wishlist(product_id):
    if not session.get('user_id'):
        flash('Log in to add this item to your wishlist.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    product = Product.query.get(product_id)

    if product not in user.wishlist:
        user.wishlist.append(product)
        db.session.commit()
        flash('Added to your wishlist.')
    else:
        flash('This item is already in your wishlist.')

    return redirect(url_for('view_product', id=product_id))

@app.route('/wishlist')
def wishlist():
    if not session.get('user_id'):
        flash('Log in to view your wishlist.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('wishlist.html', products=user.wishlist)

# Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)