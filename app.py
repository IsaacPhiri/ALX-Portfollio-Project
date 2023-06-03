from datetime import timedelta
from time import gmtime
from flask import Flask, render_template, url_for, redirect, flash, current_app, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField, SelectField, DateField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, EqualTo
from flask_bcrypt import Bcrypt
import re
import sqlite3
import os
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer as Serializer, BadSignature, SignatureExpired
from datetime import datetime

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'VJKHBHVFKHFKVJBH'
db = SQLAlchemy(app)
app.secret_key = os.urandom(24)
app.permanent_session_lifetime = timedelta(hours=3)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'john_doe@gmail.com'
app.config['MAIL_PASSWORD'] = 'xxxxxxxxxx'
app.config['MAIL_DEFAULT_SENDER'] = 'john_doe@gmail.com'
mail = Mail(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
      return User.query.get(int(user_id))

class User(db.Model, UserMixin):
      id = db.Column(db.Integer, primary_key=True)
      username = db.Column(db.String(20), nullable=True)
      lastname = db.Column(db.String(20), nullable=True)
      firstname = db.Column(db.String(20), nullable=True)
      email = db.Column(db.String(40), nullable=True, unique=True)
      password = db.Column(db.String(80), nullable=True)
      ######### test code here ############
      packages = db.relationship('Package', backref='user')
      deliveries = db.relationship('Delivery', backref='user')
      #####################################

      def get_reset_password_token(self):
        """Generates a password reset token for the user."""
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}) #.decode('utf-8')

      @staticmethod
      def verify_reset_password_token(token):
        """Verifies a password reset token and returns the user if valid."""
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return None
        return User.query.get(data['user_id'])

################################################################################################
      def create_delivery(self, package, driver, description, delivery_date):
        # create a new delivery object
        delivery = Delivery(packages=[package], driver=driver, description=description,
                            delivery_date=datetime.strptime(delivery_date, '%Y-%m-%d'), user=self)
        # add the delivery to the package's deliveries relationship
        package.delivery = delivery
        # add the delivery to the driver's deliveries relationship
        driver.deliveries.append(delivery)
        # commit the changes to the database
        db.session.add(delivery)
        db.session.commit()
        return delivery

      def add_package(self, package_name, description, location):
        package = Package(package_name=package_name, description=description, location=location, user=self)
        db.session.add(package)
        db.session.commit()
        return package

      def cancel_delivery(self, delivery):
        delivery.cancel()
        db.session.commit()

      def delete_package(self, package):
        package.delete()
        db.session.commit()

      def confirm_receipt(self, delivery):
        delivery.confirm_receipt()
        db.session.commit()



class Package(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        package_name = db.Column(db.String(20), nullable=True)
        description = db.Column(db.String(80), nullable=True)
        location = db.Column(db.String(20), nullable=True)
        Drivers = db.relationship('Driver', backref='package')
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
        delivery_id = db.Column(db.Integer, db.ForeignKey('delivery.id'))

        def save(self):
            db.session.add(self)
            db.session.commit()

        def delete(self):
            db.session.delete(self)
            db.session.commit()

class Driver(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        first_name = db.Column(db.String(20), nullable=True)
        last_name = db.Column(db.String(20), nullable=True)
        contact = db.Column(db.Integer, nullable=True)
        nrc = db.Column(db.Integer, nullable=True)
        license_plate = db.Column(db.String(10), nullable=True)
        car_model = db.Column(db.String(20), nullable=True)
        package_id = db.Column(db.Integer, db.ForeignKey('package.id'))
        deliveries = db.relationship('Delivery', backref='driver')

        def set_delivery_status(self, delivery, status):
            delivery.set_status(status)
            db.session.commit()

class DeliveryStatus:
        Open = "Open"
        InTransit = "In Transit"
        Delivered = "Delivered"

class Delivery(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        packages = db.relationship('Package', backref='delivery')
        driver_id = db.Column(db.Integer, db.ForeignKey('driver.id'))
        delivery_date = datetime.now()
        status = DeliveryStatus.Open
        delivered_date = datetime.now()
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

        def save(self):
            db.session.add(self)
            db.session.commit()

        def set_status(self, status):
            self.status = status
            db.session.commit()

        def cancel(self):
            self.status = DeliveryStatus.Cancelled
            db.session.commit()

        def confirm_receipt(self):
            self.status = DeliveryStatus.Delivered
            self.delivered_date = datetime.now()
            db.session.commit()

#### FORMS #########
class DriverForm(FlaskForm):
        first_name = StringField('First Name', validators=[DataRequired(), Length(max=20)])
        last_name = StringField('Last Name', validators=[DataRequired(), Length(max=20)])
        contact = IntegerField('Contact', validators=[DataRequired()])
        nrc = IntegerField('NRC', validators=[DataRequired()])
        license_plate = StringField('License Plate', validators=[DataRequired(), Length(max=10)])
        car_model = StringField('Car Model', validators=[DataRequired(), Length(max=20)])
        submit = SubmitField('Create Driver')

class PackageForm(FlaskForm):
        name = StringField('Name', validators=[DataRequired(), Length(min=2, max=20)])
        description = TextAreaField('Description', validators=[DataRequired(), Length(max=80)])
        location = StringField('Location', validators=[DataRequired(), Length(min=2, max=20)])
        submit = SubmitField('Create Package')

class DeliveryForm(FlaskForm):
        package = SelectField('Package', validators=[DataRequired()])
        driver = SelectField('Driver', validators=[DataRequired()])
        description = TextAreaField('Description', validators=[DataRequired(), Length(max=80)])
        delivery_date = DateField('Delivery Date', format='%Y-%m-%d', validators=[DataRequired()])
        submit = SubmitField('Create Delivery')

class PackageForm(FlaskForm):
        package_name = StringField('Name', validators=[DataRequired(), Length(max=20)])
        description = TextAreaField('Description', validators=[DataRequired(), Length(max=200)])
        location = StringField('Location', validators=[DataRequired(), Length(max=40)])
        submit = SubmitField('Add Package')
################################################################################################

class PasswordValidator:
    def __init__(self, message=None):
        if not message:
            message = 'Password must have at least 6 characters, 1 capital letter, 1 number, and 1 special character'
        self.message = message

    def __call__(self, form, field):
        password = form.data
        password = field.data

        if len(password) < 6:
            raise ValidationError(self.message)
        if not re.search("[A-Z]", password):
            raise ValidationError(self.message)
        if not re.search("[0-9]", password):
            raise ValidationError(self.message)
        if not re.search("[@#$%^&+=]", password):
            raise ValidationError(self.message)


class SignupForm(FlaskForm):
      username = StringField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder": "Username"})

      firstname = StringField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder": "Firstname"})

      lastname = StringField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder": "Lastname"})

      email = StringField(validators=[InputRequired(), Length(
            min=4, max=40)], render_kw={"placeholder": "Email"})

      password = PasswordField(validators=[InputRequired(), Length(
            min=6, max=20), PasswordValidator()], render_kw={"placeholder": "Password"})

      confirm_password = PasswordField(validators=[InputRequired(), Length(
            min=6, max=20), PasswordValidator()], render_kw={"placeholder": "Confirm Password"})

      submit = SubmitField("SignUp")

      def validate_username(self, username):
            existing_user_username = User.query.filter_by(
                  username=username.data).first()

            if existing_user_username:
                  raise ValidationError(
                        "That username already exists. Plaese choose a different one.")

      def validate_email(self, email):
            existing_user_email = User.query.filter_by(
                  email=email.data).first()

            if existing_user_email:
                  raise ValidationError(
                        "That email already exists. Plaese choose a different one.")

class ForgotMyPassword(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(
        min=4, max=40)], render_kw={"placeholder": "Email"})
    submit = SubmitField("Reset Password")

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()

        if not user:
            raise ValidationError(
                "There is no account associated with that email.")

        # generate a password reset token
        token = user.get_reset_password_token()

        # send a password reset email to the user
        send_password_reset_email(user, token)

        # inform the user that a password reset email has been sent
        flash('An email has been sent with instructions to reset your password.', 'info')


class ResetPasswordForm(FlaskForm):
     password = PasswordField('New Password', validators=[DataRequired()])
     confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
     submit = SubmitField('Reset Password')


class LoginForm(FlaskForm):
      # CODE WILL BE REFACTORED TO ALLOW USER TO LOGIN USING USERNAME OR EMAIL
      #username = StringField(validators=[InputRequired(), Length(
      #      min=4, max=20)], render_kw={"placeholder": "Username"})

      email = StringField(validators=[InputRequired(), Length(
            min=15, max=40)], render_kw={"placeholder": "Email"})

      password = PasswordField(validators=[InputRequired(), Length(
            min=4, max=20)], render_kw={"placeholder": "Password"})

      submit = SubmitField("Login")

def send_password_reset_email(user, token):
      msg = Message('Password Reset Request',
                  recipients=[user.email])

      msg.body = f'''To reset your password, visit the following link:
      {url_for('reset_password', token=token, _external=True)}
      If you did not make this request then simply ignore this email and no changes will be made.
      '''
      mail.send(msg)

@app.route('/')
def index():
    #with app.app_context():
    #    db.create_all()
    return render_template('index.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotMyPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            # generate a password reset token
            token = user.get_reset_password_token()

            # send a password reset email to the user
            send_password_reset_email(user, token)

            # inform the user that a password reset email has been sent
            flash('An email has been sent with instructions to reset your password.', 'info')
        
        # always redirect to the homepage after a password reset request
        return redirect(url_for('login'))

    return render_template('fgp.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    form = ResetPasswordForm()
    user = User.verify_reset_password_token(token)
    if not user:
        flash('Invalid or expired token', 'warning')
        return redirect(url_for('forgot_password')) #Code to reset password has bug here
    if request.method == 'POST':                    #Token issue
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if not password:
            flash('Please enter a new password', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match', 'danger')
        else:
            user.password_hash = bcrypt.generate_password_hash(password)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.template_filter('length')
def length(s):
    return len(s)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Check if user is logged in, redirect to login page if not
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    username = current_user.username
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Connect to database
    conn = sqlite3.connect('instance/database.db')
    c = conn.cursor()

    # Execute an SQL command to create a table
    # Check if deliveries table exists
    c.execute('''SELECT name FROM sqlite_master WHERE type='table' AND name='deliveries' ''')
    table_exists = c.fetchone()

    # If table doesn't exist, create it
    if not table_exists:
        c.execute('''CREATE TABLE deliveries
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       recipient_name TEXT,
                       delivery_address TEXT,
                       delivery_status TEXT)''')

    # Commit the changes to the database
    conn.commit()
    
    # Get list of deliveries
    c.execute('SELECT * FROM deliveries')
    deliveries = c.fetchall()
    
    # Get list of drivers
    c.execute('SELECT * FROM driver')
    drivers = c.fetchall()
    
    # Close the connection
    conn.close()

    # Count deliveries by status
    in_transit_count = 0
    delivered_count = 0
    scheduled_count = 0
    for delivery in deliveries:
        if delivery[3] == 'in_transit':
            in_transit_count += 1
        elif delivery[3] == 'delivered':
            delivered_count += 1
        elif delivery[3] == 'scheduled':
            scheduled_count += 1
    
    # Filter and sort deliveries based on user input
    filter = request.args.get('filter')
    sort_by = request.args.get('sort_by')
    search = request.args.get('search')
    if filter:
        deliveries = [delivery for delivery in deliveries if delivery[3] == filter]
    if sort_by:
        deliveries = sorted(deliveries, key=lambda delivery: delivery[sort_by])
    if search:
        deliveries = [delivery for delivery in deliveries if search.lower() in delivery[1].lower() or search.lower() in delivery[2].lower()]
    
    # Render the dashboard template with deliveries, counts, and drivers
    return render_template('dashboard.html', deliveries=deliveries, in_transit_count=in_transit_count, delivered_count=delivered_count, scheduled_count=scheduled_count, drivers=drivers, username=username)

# Route for the delivery details view
@app.route('/delivery/<int:delivery_id>', methods=['GET'])
def delivery_details(delivery_id):
    # Check if user is logged in, redirect to login page if not
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    username = current_user.username

    # Connect to database
    conn = sqlite3.connect('instance/database.db')
    c = conn.cursor()

    # Get the delivery with the given id
    c.execute('SELECT * FROM deliveries WHERE id = ?', (delivery_id,))
    delivery = c.fetchone()

    # Close the connection
    conn.close()

    # Render the delivery details template with the delivery information
    return render_template('delivery_details.html', delivery=delivery, username=username)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    # log out user
    logout_user()
    # clear session data
    session.clear()
    # redirect to login page
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                # set logged_in key in session object
                session['logged_in'] = True
                session["user"] = "user1"
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        password_one = (form.password.data)
        password_two = (form.confirm_password.data)
        if password_one != password_two:
            error_message = "Passwords don't match."
            return jsonify({'error': error_message})
        else:
            hashed_password = bcrypt.generate_password_hash(password_one)
            new_user = User(username=form.username.data, firstname=form.firstname.data, lastname=form.lastname.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            success_message = "Account created successfully."
            return jsonify({'success': success_message})
            #return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/drivers/new', methods=['GET', 'POST'])
def create_driver():
    form = DriverForm()
    if form.validate_on_submit():
        driver = Driver(first_name=form.first_name.data,
                        last_name=form.last_name.data,
                        contact=form.contact.data,
                        nrc=form.nrc.data,
                        car_model=form.car_model.data,
                        license_plate=form.license_plate.data)
        db.session.add(driver)
        db.session.commit()
        flash('Driver created successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_driver.html', title='Create Driver', form=form)

@app.route('/add_package', methods=['GET', 'POST'])
def add_package():
    user = User.query.get(1) # replace with user object obtained from login session
    form = PackageForm()
    if form.validate_on_submit():
        package_name = form.package_name.data
        description = form.description.data
        location = form.location.data
        user.add_package(package_name, description, location)
        return redirect(url_for('dashboard'))
    return render_template('add_package.html', form=form)

#Program starts here   
if __name__ == '__main__':
    app.app_context().push()
    db.create_all()
    app.run(debug=True)