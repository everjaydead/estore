from flask import Flask, render_template, redirect, url_for, session, request, flash
from datetime import datetime
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_secret_key')  # Use environment variable for production

def get_db():
    db = sqlite3.connect('joone.db')
    return db

def fetch_products():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM products") 
    products = cursor.fetchall()
    db.close()
    return {str(product[0]): {'name': product[1], 'price': product[2], 'image': product[3], 'year': product[4]} for product in products}

@app.route('/')
def index():
    products = fetch_products()  # Fetch products from the DB
    year = request.args.get('year')
    if year:
        try:
            year = int(year)
        except ValueError:
            year = None
    else:
        year = 2020

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

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')  
        try:
            cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)", (username, hashed_password))
            db.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except Exception as e:
            print(e)
            db.rollback()
            flash('An error occurred during registration.')
            return redirect(url_for('register'))
        finally:
            db.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        db.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['is_admin'] = user[3]  
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
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
    product = fetch_products().get(id)
    if product:
        print(f"Image path being used: {product['image']}")  # Debug print
        image_path = url_for('static', filename=product['image'])
        print(f"Full image URL: {image_path}")  # Debug print
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

        # Strip 'static/' from the beginning of the image path if it exists
        if image.startswith('static/'):
            image = image[7:]  # Remove first 7 characters ('static/')

        if not name or not price or not image or not year:
            flash('Please fill in all fields.')
            return redirect(url_for('add_product'))

        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("INSERT INTO products (name, price, image, year) VALUES (?, ?, ?, ?)", 
                           (name, float(price), image, int(year)))
            db.commit()
            flash('Product added successfully!')
            return redirect(url_for('index'))

        except Exception as e:
            print(e)
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

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        image = request.form['image']
        year = request.form['year']

        # Strip 'static/' from the beginning of the image path if it exists
        if image.startswith('static/'):
            image = image[7:]  # Remove first 7 characters ('static/')

        if not name or not price or not image or not year:
            flash('Please fill in all fields.')
            return redirect(url_for('edit_product', id=id))

        try:
            cursor.execute("UPDATE products SET name = ?, price = ?, image = ?, year = ? WHERE id = ?", 
                           (name, float(price), image, int(year), id))
            db.commit()
            flash('Product details updated successfully!')
            return redirect(url_for('manage_products'))
        except Exception as e:
            print(e)
            flash('An error occurred while updating the product.')
            return redirect(url_for('edit_product', id=id))
    else:
        cursor.execute("SELECT * FROM products WHERE id = ?", (id,))
        product = cursor.fetchone()
        db.close()
        
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

    db = get_db()
    
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password and new_password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('profile'))

        cursor = db.cursor()
        try:
            if new_password:
                hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                cursor.execute("UPDATE users SET username = ?, password = ? WHERE id = ?", (username, hashed_password, user_id))
            else:
                cursor.execute("UPDATE users SET username = ? WHERE id = ?", (username, user_id))

            db.commit()
            flash('Profile updated successfully!')
            return redirect(url_for('profile'))

        except Exception as e:
            print(e)
            db.rollback()
            flash('An error occurred while updating the profile.')
            return redirect(url_for('profile'))
    
    cursor = db.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    db.close()

    return render_template('profile.html', user=user)

@app.route('/order_history')
def order_history():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view your order history.')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT orders.id, products.name, orders.quantity, orders.order_date FROM orders JOIN products ON orders.product_id = products.id WHERE orders.user_id = ?", (user_id,))
    orders = cursor.fetchall()
    db.close()

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

    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'POST':
        user_id = request.form['user_id']
        is_admin = request.form['is_admin']
        cursor.execute("UPDATE users SET is_admin = ? WHERE id = ?", (is_admin, user_id))
        db.commit()
        flash('User updated successfully.')
    
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    db.close()

    return render_template('users.html', users=users)

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

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], current_password):
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user[0]))
            db.commit()
            flash('Password changed successfully!')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Current password is incorrect.')
            return redirect(url_for('change_admin_password'))

    return render_template('change_admin_password.html')

if __name__ == '__main__':
    app.run(debug=True)
