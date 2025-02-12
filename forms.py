from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, EmailField, DecimalField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length, Email, Optional

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    image = StringField('Image URL', validators=[DataRequired()])
    brand = StringField('Brand', validators=[DataRequired()])
    category = SelectField('Category', coerce=int, validators=[DataRequired()])
    stock = IntegerField('Stock', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ReviewForm(FlaskForm):
    rating = IntegerField('Rating', validators=[DataRequired()])
    comment = TextAreaField('Comment')
    submit = SubmitField('Submit Review')

class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired(), Length(min=2, max=50)])
    description = TextAreaField('Category Description', validators=[Optional(), Length(max=200)])
    is_active = BooleanField('Active Category', default=True)
    submit = SubmitField('Create Category')

class EditUserProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    profile_picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    bio = TextAreaField('Bio', validators=[Optional(), Length(max=300)])
    password = PasswordField('Password', validators=[Optional(), Length(min=8)])
    submit = SubmitField('Update Profile')

class PasswordResetRequestForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')
    
class PasswordResetForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Reset Password')

class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Optional(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[EqualTo('password', message='Passwords must match')])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], default='user')
    is_active = BooleanField('Active Account')
    is_locked = BooleanField('Lock Account')
    submit = SubmitField('Update')