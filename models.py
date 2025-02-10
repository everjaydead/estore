from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

wishlist_items = db.Table('wishlist_items',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('product_id', db.Integer, db.ForeignKey('product.id'), primary_key=True),
    extend_existing=True
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), nullable=False, default='user')
    is_active = db.Column(db.Boolean, default=True)
    is_locked = db.Column(db.Boolean, default=False)
    wishlist = db.relationship('Product', secondary=wishlist_items, back_populates='wishlisted_by')
    reviews = db.relationship('Review', cascade='all, delete-orphan', back_populates='user')
    saved_items = db.relationship('SavedForLater', back_populates='user')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    children = db.relationship('Category', backref=db.backref('parent', remote_side=[id]), lazy='dynamic')
    products = db.relationship('Product', back_populates='category')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, nullable=False, default=0)
    featured = db.Column(db.Boolean, default=False)  # Featured field
    popularity = db.Column(db.Integer, default=0)  # Popularity field
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)

    category = db.relationship('Category', back_populates='products')
    wishlisted_by = db.relationship('User', secondary=wishlist_items, back_populates='wishlist')
    reviews = db.relationship('Review', back_populates='product', cascade='all, delete-orphan')
    saved_for_later = db.relationship('SavedForLater', back_populates='product', cascade='all, delete-orphan')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='order_user_fk'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id', name='order_product_fk'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id', ondelete='CASCADE', name='fk_review_product'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE', name='fk_review_user'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    review_date = db.Column(db.DateTime, default=datetime.utcnow)

    product = db.relationship('Product', back_populates='reviews')
    user = db.relationship('User', back_populates='reviews')

class SavedForLater(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE', name='fk_sfl_user'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id', ondelete='CASCADE', name='fk_sfl_product'), nullable=False)
    date_saved = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='saved_items')
    product = db.relationship('Product', back_populates='saved_for_later')