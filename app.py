from flask import Flask, render_template, redirect, url_for, session, request, flash
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_mail import Mail, Message
import requests
import os
import base64
from forms import (RegistrationForm, LoginForm, ProductForm,
                   ReviewForm, EditUserProfileForm, PasswordResetRequestForm,
                   PasswordResetForm, EditUserForm)
from models import db, User, Product, Order, Review, SavedForLater, Category

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-here')
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Check for DATABASE_URL and ensure it uses postgresql+psycopg2 as the prefix to make it Heroku-compatible
uri = os.getenv("DATABASE_URL", f'sqlite:///{os.path.join(os.path.abspath(os.path.dirname(__file__)), "joone.db")}')
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql+psycopg2://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail server configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')

# M-Pesa configurations
MPESA_CONSUMER_KEY = os.environ.get('MPESA_CONSUMER_KEY', 'MrokSMjOLMuyNkB0G53KBRcaLP1gdvbb4AJUobP3vCYMVxYG')
MPESA_CONSUMER_SECRET = os.environ.get('MPESA_CONSUMER_SECRET', 'acoffT5LyPaGhV4WQMMRyJjxZWR9MzOmHW3gDBHtRCvlNOtpc7AiOarKm7A5JsCy')
MPESA_SHORTCODE = os.environ.get('MPESA_SHORTCODE', 'your-shortcode')
MPESA_PASSKEY = os.environ.get('MPESA_PASSKEY', 'your-passkey')
MPESA_ENVIRONMENT = os.environ.get('MPESA_ENVIRONMENT', 'sandbox')  # Change to 'production' for live environment
MPESA_BASE_URL = 'https://sandbox.safaricom.co.ke' if MPESA_ENVIRONMENT == 'sandbox' else 'https://api.safaricom.co.ke'

mail = Mail(app)
s = Serializer(app.secret_key)

db.init_app(app)
migrate = Migrate(app, db)

def send_password_reset_email(user_email, reset_url):
    try:
        msg = Message("Password Reset Request", recipients=[user_email])
        msg.body = f"To reset your password, click the following link: {reset_url}. If you did not make this request, simply ignore this email."
        mail.send(msg)
        flash("An email with password reset instructions has been sent.", "success")
    except Exception as e:
        flash("Failed to send email. Please try again later.", "error")

def save_picture(form_picture):
    # Implement file saving logic (e.g., saving profile pictures)
    pass  # Add functionality for saving images

def get_access_token():
    """Generate M-Pesa API access token."""
    api_url = f"{MPESA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials"
    response = requests.get(api_url, auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET))
    json_response = response.json()
    return json_response['access_token']

def lipa_na_mpesa_online(total_price, phone_number):
    """Make payment request to M-Pesa for the specified amount."""
    access_token = get_access_token()
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    password = base64.b64encode(f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}".encode()).decode('utf-8')
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "BusinessShortCode": MPESA_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": total_price,
        "PartyA": phone_number,
        "PartyB": MPESA_SHORTCODE,
        "PhoneNumber": phone_number,
        "CallBackURL": url_for('mpesa_callback', _external=True),
        "AccountReference": "Cart Payment",
        "TransactionDesc": "Payment for cart items"
    }
    api_url = f"{MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest"
    
    response = requests.post(api_url, json=payload, headers=headers)
    return response.json()

@app.context_processor
def inject_enumeration():
    return {'enumerate': enumerate}

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

@app.context_processor
def inject_globals():
    return dict(int=int)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return render_template('500.html'), 500

@app.route('/')
def index():
    featured_products = Product.query.filter_by(featured=True).all()
    categories = Category.query.all() 
    recommended_products = Product.query.order_by(Product.popularity.desc()).limit(4).all()

    return render_template('index.html', 
        featured_products=featured_products, 
        categories=categories, 
        recommended_products=recommended_products)

@app.route('/products', methods=['GET'])
def products():
    search_query = request.args.get('search', '')
    min_price = request.args.get('min_price', type=float, default=0)
    max_price = request.args.get('max_price', type=float, default=100000)
    category_id = request.args.get('category_id', type=int)
    
    filters = [Product.price >= min_price, Product.price <= max_price]
    if search_query:
        filters.append(Product.name.ilike(f'%{search_query}%'))
    if category_id is not None:
        filters.append(Product.category_id == category_id)

    products = Product.query.filter(*filters).all()
    categories = Category.query.all()

    return render_template('products.html', products=products, categories=categories)

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if not session.get('user_id'):
        flash('Please log in to checkout.')
        return redirect(url_for('login'))

    cart = session.get('cart', {})
    cart_items = []
    total_price = 0

    for product_id, quantity in cart.items():
        product = db.session.get(Product, int(product_id))
        if product:
            if product.stock < quantity:
                flash(f"Sorry, we only have {product.stock} of {product.name} in stock.", 'error')
                return redirect(url_for('cart'))

            total_price += product.price * quantity
            cart_items.append({'product': product, 'quantity': quantity})

    if request.method == 'POST':
        phone_number = request.form.get('phone')
        if not cart_items:
            flash('Your cart is empty.')
            return redirect(url_for('cart'))

        payment_response = lipa_na_mpesa_online(total_price, phone_number)
        flash(payment_response.get('CustomerMessage', 'An error occurred during payment initiation.'))

    return render_template('checkout.html', cart_items=cart_items, total_price=total_price)

@app.route('/mpesa_callback', methods=['POST'])
def mpesa_callback():
    # Logic to handle callback from M-Pesa
    data = request.get_json()
    # Process the data based on your requirements
    return "Callback received", 200

@app.route('/product/<int:id>')
def view_product(id):
    product = db.session.get(Product, id)
    if product:
        review_form = ReviewForm()
        image_path = url_for('static', filename=product.image)
        return render_template('product.html', product=product, image_url=image_path, review_form=review_form)
    flash('Product not found.')
    return redirect(url_for('products'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('products'))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        is_first_user = User.query.count() == 0
        new_user = User(username=username, email=email, password=hashed_password, is_admin=is_first_user)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('User with that username or email already exists.')
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.')

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('products'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Login successful!')
            return redirect(url_for('products'))
        else:
            flash('Invalid username or password.')
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!')
    return redirect(url_for('products'))

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if session.get('user_id'):
        return redirect(url_for('products'))
    
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='email-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            send_password_reset_email(user.email, reset_url)
        
        flash('Check your email for a password reset link.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-reset-salt', max_age=86400)
    except Exception:
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('reset_password_request'))
    
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
            db.session.commit()
            flash('Your password has been updated.', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html', form=form)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('user_id'):
        flash('Please log in to view your profile.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    form = EditUserProfileForm(obj=user)

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        if form.profile_picture.data:
            picture_file = save_picture(form.profile_picture.data)  # Implement save_picture to handle file saving
            user.profile_picture = picture_file
        user.bio = form.bio.data

        if form.password.data:
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', form=form)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if not session.get('user_id'):
        flash("You must be logged in to add items to your cart.")
        return redirect(url_for('login'))

    product = db.session.get(Product, product_id)
    if not product:
        flash("Product not found.")
        return redirect(url_for('products'))

    session.setdefault('cart', {})
    cart = session['cart']
    cart[str(product_id)] = cart.get(str(product_id), 0) + 1

    if product.stock < cart[str(product_id)]:
        flash(f"Only {product.stock} of {product.name} is available in stock.", "warning")
        return redirect(url_for('cart'))

    session.modified = True
    flash(f"Added {product.name} to your cart.")
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    if not session.get('user_id'):
        flash('You must be logged in to view your cart.')
        return redirect(url_for('login'))

    cart = session.get('cart', {})
    cart_items = []
    total_price = 0

    for product_id, quantity in cart.items():
        product = db.session.get(Product, int(product_id))
        if product:
            item_total = product.price * quantity
            cart_items.append({
                'product': product,
                'quantity': quantity,
                'total': item_total
            })
            total_price += item_total

    user_id = session['user_id']
    saved_items = SavedForLater.query.filter_by(user_id=user_id).all()
    
    recommendations = []
    if cart_items:
        product_ids = [item['product'].id for item in cart_items]
        recommendations = Product.query.filter(Product.id.notin_(product_ids)).limit(3).all()

    return render_template('cart.html',
                         cart_items=cart_items,
                         saved_items=saved_items,
                         total_price=total_price,
                         recommendations=recommendations)

@app.route('/update_cart/<int:product_id>', methods=['POST'])
def update_cart(product_id):
    if 'cart' not in session:
        flash('Your cart is empty.')
        return redirect(url_for('cart'))

    quantity = request.form.get('quantity', type=int)
    if quantity is None or quantity < 0:
        flash('Invalid quantity.')
        return redirect(url_for('cart'))

    product = db.session.get(Product, product_id)
    if not product or product.stock < quantity:
        flash(f"Cannot update to {quantity}. Only {product.stock} available.", "warning")
        return redirect(url_for('cart'))

    if quantity == 0:
        session['cart'].pop(str(product_id), None)
    else:
        session['cart'][str(product_id)] = quantity
    
    session.modified = True
    flash('Cart updated successfully.')
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'cart' in session:
        cart = session['cart']
        if str(product_id) in cart:
            del cart[str(product_id)]
            session.modified = True
            flash('Item removed from cart.')
    return redirect(url_for('cart'))

@app.route('/save_for_later/<int:product_id>', methods=['POST'])
def save_for_later(product_id):
    if not session.get('user_id'):
        flash('Log in to save this item for later.')
        return redirect(url_for('login'))

    user_id = session['user_id']
    existing_item = SavedForLater.query.filter_by(user_id=user_id, product_id=product_id).first()

    if not existing_item:
        new_saved_item = SavedForLater(user_id=user_id, product_id=product_id)
        db.session.add(new_saved_item)
        try:
            db.session.commit()
            flash('Item saved for later.')
        except Exception as e:
            db.session.rollback()
            flash('Error saving item for later.')
    else:
        flash('Item is already saved for later.')

    return redirect(url_for('cart'))

@app.route('/add_to_wishlist/<int:product_id>', methods=['POST'])
def add_to_wishlist(product_id):
    if not session.get('user_id'):
        flash('Log in to add this item to your wishlist.')
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    product = db.session.get(Product, product_id)

    if not product:
        flash('Product not found.')
        return redirect(url_for('products'))

    if product not in user.wishlist:
        user.wishlist.append(product)
        try:
            db.session.commit()
            flash('Added to your wishlist.')
        except Exception as e:
            db.session.rollback()
            flash('Error adding to wishlist.')
    else:
        flash('This item is already in your wishlist.')

    return redirect(url_for('view_product', id=product_id))

@app.route('/wishlist')
def wishlist():
    if not session.get('user_id'):
        flash('Please log in to view your wishlist.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    wishlist_items = user.wishlist if user else []

    return render_template('wishlist.html', wishlist_items=wishlist_items)

@app.route('/remove_from_wishlist/<int:product_id>', methods=['POST'])
def remove_from_wishlist(product_id):
    if not session.get('user_id'):
        flash('Please log in to modify your wishlist.')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    product = Product.query.get(product_id)

    if user and product in user.wishlist:
        user.wishlist.remove(product)
        try:
            db.session.commit()
            flash('Item removed from wishlist.')
        except Exception as e:
            db.session.rollback()
            flash('Error removing item from wishlist.')

    return redirect(url_for('wishlist'))

@app.route('/add_review/<int:product_id>', methods=['POST'])
def add_review(product_id):
    if not session.get('user_id'):
        flash('You must be logged in to leave a review.')
        return redirect(url_for('login'))

    rating = request.form.get('rating', type=int)
    comment = request.form.get('comment')

    if not rating or rating < 1 or rating > 5:
        flash('Please provide a valid rating (1-5).')
        return redirect(url_for('view_product', id=product_id))

    review = Review(user_id=session['user_id'], product_id=product_id, rating=rating, comment=comment)

    try:
        db.session.add(review)
        db.session.commit()
        flash('Review added successfully!')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while adding your review.')

    return redirect(url_for('view_product', id=product_id))

@app.route('/order_history')
def order_history():
    if not session.get('user_id'):
        flash('Please log in to view your order history.')
        return redirect(url_for('login'))

    orders = Order.query.filter_by(user_id=session['user_id']).order_by(Order.order_date.desc()).all()

    return render_template('order_history.html', orders=orders)

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('index'))

    total_users = User.query.count()
    total_orders = Order.query.count()
    total_products = Product.query.count()
    recent_orders = Order.query.order_by(Order.order_date.desc()).limit(5).all()

    return render_template('admin/dashboard.html', total_users=total_users, total_orders=total_orders, total_products=total_products, recent_orders=recent_orders)

@app.route('/admin/products')
def admin_products():
    if not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('index'))

    products = Product.query.all()
    return render_template('admin/products.html', products=products)

@app.route('/admin/add_product', methods=['GET', 'POST'])
def admin_add_product():
    if not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('index'))

    form = ProductForm()
    form.category.choices = [(c.id, c.name) for c in Category.query.order_by('name').all()]
    if form.validate_on_submit():
        product = Product(
            name=form.name.data,
            price=form.price.data,
            image=form.image.data,
            brand=form.brand.data,
            category_id=form.category.data,
            stock=form.stock.data
        )
        try:
            db.session.add(product)
            db.session.commit()
            flash('Product added successfully!')
            return redirect(url_for('admin_products'))
        except Exception as e:
            db.session.rollback()
            flash('Error adding product.')

    return render_template('admin/add_product.html', form=form)

@app.route('/admin/edit_product/<int:id>', methods=['GET', 'POST'])
def admin_edit_product(id):
    if not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('index'))

    product = db.session.get(Product, id)
    if not product:
        flash('Product not found.')
        return redirect(url_for('admin_products'))

    form = ProductForm(obj=product)
    form.category.choices = [(c.id, c.name) for c in Category.query.order_by('name').all()]
    if form.validate_on_submit():
        product.name = form.name.data
        product.price = form.price.data
        product.image = form.image.data
        product.brand = form.brand.data
        product.category_id = form.category.data
        product.stock = form.stock.data

        try:
            db.session.commit()
            flash('Product updated successfully!')
            return redirect(url_for('admin_products'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating product.')

    return render_template('admin/edit_product.html', form=form, product=product)

@app.route('/admin/delete_product/<int:id>', methods=['POST'])
def admin_delete_product(id):
    if not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('index'))

    product = db.session.get(Product, id)
    if product:
        try:
            db.session.delete(product)
            db.session.commit()
            flash('Product deleted successfully!')
        except Exception as e:
            db.session.rollback()
            flash('Error deleting product.')
    else:
        flash('Product not found.')

    return redirect(url_for('admin_products'))

@app.route('/admin/categories', methods=['GET', 'POST'])
def admin_categories():
    if not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        parent_id = request.form.get('parent_id', type=int)
        category = Category(name=name, parent_id=parent_id)

        try:
            db.session.add(category)
            db.session.commit()
            flash('Category added successfully!')
        except Exception as e:
            db.session.rollback()
            flash('Error adding category.')

    categories = Category.query.all()
    return render_template('admin/categories.html', categories=categories)

@app.route('/admin/edit_category/<int:id>', methods=['GET', 'POST'])
def admin_edit_category(id):
    if not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('index'))

    category = db.session.get(Category, id)
    if not category:
        flash('Category not found.')
        return redirect(url_for('admin_categories'))

    if request.method == 'POST':
        category.name = request.form['name']
        category.parent_id = request.form.get('parent_id', type=int)

        try:
            db.session.commit()
            flash('Category updated successfully!')
            return redirect(url_for('admin_categories'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating category.')

    categories = Category.query.all()
    return render_template('admin/edit_category.html', category=category, categories=categories)

@app.route('/admin_users')
def admin_users():
    if not session.get('user_id') or not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('index'))

    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin_edit_user/<int:id>', methods=['GET', 'POST'])
def admin_edit_user(id):
    if not session.get('user_id') or not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('index'))

    user = db.session.get(User, id)
    if not user:
        flash('User not found.')
        return redirect(url_for('admin_users'))

    form = EditUserForm(obj=user)
    
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        if form.password.data:
            user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user.role = form.role.data
        user.is_active = form.is_active.data
        user.is_locked = form.is_locked.data

        try:
            db.session.commit()
            flash('User updated successfully!')
            return redirect(url_for('admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {e}')

    return render_template('admin/edit_user.html', form=form, user=user)

@app.route('/admin_delete_category/<int:id>', methods=['POST'])
def admin_delete_category(id):
    if not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('index'))

    category = db.session.get(Category, id)
    if category:
        try:
            db.session.delete(category)
            db.session.commit()
            flash('Category deleted successfully!')
        except Exception as e:
            db.session.rollback()
            flash('Error deleting category.')
    else:
        flash('Category not found.')

    return redirect(url_for('admin_categories'))

@app.route('/admin_toggle_admin/<int:user_id>', methods=['POST'])
def admin_toggle_admin(user_id):
    if not session.get('is_admin'):
        flash('Access denied.')
        return redirect(url_for('index'))

    user = db.session.get(User, user_id)
    if user:
        user.is_admin = not user.is_admin
        try:
            db.session.commit()
            status = "admin" if user.is_admin else "regular user"
            flash(f"{user.username} is now a {status}.")
        except Exception as e:
            db.session.rollback()
            flash('Error toggling admin status.')
    else:
        flash('User not found.')

    return redirect(url_for('admin_users'))

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Handle form submission logic here, e.g., send email
        flash('Thank you for reaching out. We will get back to you shortly.', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

def init_db():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)