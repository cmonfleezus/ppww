from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_bootstrap import Bootstrap
import requests
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, DateField
from wtforms.validators import DataRequired, Email, Length, InputRequired, EqualTo
from datetime import date
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
from werkzeug.utils import secure_filename


secret_string = str(os.environ.get("SECRET_KEY"))

app = Flask(__name__)
app.secret_key = secret_string
Bootstrap(app)


app.config["IMAGE_UPLOADS"] = os.path.abspath('static/img/uploads')
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["PNG", "JPG", "JPEG", "GIF"]
app.config["MAX_IMAGE_FILESIZE"] = 8 * 1024 * 1024

DB_LINK = 'sqlite:///users.db'
# bazy danych
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

posts = requests.get("https://api.npoint.io/c790b4d5cab58020d391").json()

temp_flash = "" # przenoszenie flashow na kolejna strone po logout w konkretnych przypadkach

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    surname = db.Column(db.String(100))
    birthdate = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.Integer, unique=True)
    password = db.Column(db.String(100))
    accept_tos = db.Column(db.String(100))
    cart_count = db.Column(db.Integer)

    def __init__(self, username, surname, email, phone, password, birthdate, accept_tos):
        self.username = username
        self.surname = surname
        self.email = email
        self.phone = phone
        self.password = password
        self.birthdate = birthdate
        self.accept_tos = accept_tos


class Categories(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_name = db.Column(db.String(250))


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(250))
    product_name = db.Column(db.String(250))
    product_description = db.Column(db.Text)
    img_url = db.Column(db.String(500))
    price = db.Column(db.Integer)
    discount_price = db.Column(db.Integer)
    discount_turn_on = db.Column(db.Integer)


class Messages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250))
    email = db.Column(db.String(250))
    phone = db.Column(db.String(250))
    message = db.Column(db.String(250))
    date = db.Column(db.String(250))


class Koszyki(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    product_id = db.Column(db.Integer)


class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField(label="Log In")


class ZmienHaslo(FlaskForm):
    stare_haslo = PasswordField('Stare hasło', validators=[Length(min=6, max=20), InputRequired()])
    nowe_haslo = PasswordField('Nowe hasło', validators=[Length(min=6, max=20), InputRequired(),
                                                           EqualTo('powtorz_haslo', message='Hasła nie są takie same!')])
    powtorz_haslo = PasswordField('Powtórz hasło', validators=[Length(min=6, max=20), InputRequired()])
    submit = SubmitField(label="Zapisz zmiany")


class RegistrationForm(FlaskForm):
    username = StringField('Imię', validators=[Length(min=3, max=20)])
    surname = StringField('Nazwisko', validators=[Length(min=3, max=25)])
    email = StringField('Adres e-mail', validators=[Length(min=6, max=50)])
    password = PasswordField('Hasło', validators=[Length(min=6, max=20), InputRequired(),
                                                  EqualTo('confirm', message='Hasła nie są takie same!')])
    confirm = PasswordField('Powtórz hasło')
    phone = StringField('Numer telefonu', validators=[Length(max=12)])
    birthdate = DateField('Data urodzenia', format='%Y-%m-%d')
    accept_tos = BooleanField('I accept the Terms of Service and Privacy Notice (updated Jan 22, 2015)',
                              validators=[InputRequired()])
    submit = SubmitField(label="Loggg In")


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.get_id():
            return abort(403)
        elif current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def index():
    if not db.session.query(Categories).first():
        new_category1 = Categories(
            category_name="Ciasta",
        )
        new_category2 = Categories(
            category_name="Torty",
        )
        new_category3 = Categories(
            category_name="Ciasteczka",
        )
        new_category4 = Categories(
            category_name="Pączki",
        )
        db.session.add(new_category1)
        db.session.add(new_category2)
        db.session.add(new_category3)
        db.session.add(new_category4)
        db.session.commit()

    return render_template('index.html', posts=posts, current_user=current_user, all_products=Product.query.all())


@app.route('/item/<int:post_id>')
def item(post_id):
    requested_post = None
    for n in posts:
        if n["id"] == post_id:
            requested_post = n
    return render_template('item.html', post=requested_post, current_user=current_user)


@app.route("/products/<category>/<int:prod_id>")
def view_product(prod_id, category):
    product = Product.query.filter_by(id=prod_id).first()
    return render_template('view_product.html', product=product, current_user=current_user)


@app.route('/kontakt', methods=['GET', 'POST'])
def kontakt():
    if request.method == "POST":
        new_message = Messages(
            username=request.form["name"],
            email=request.form["email"],
            phone=request.form["phone"],
            message=request.form["message"],
            date=date.today(),
        )
        db.session.add(new_message)
        db.session.commit()
        flash("Wiadomość została wysłana")
        return redirect(url_for("index"))
    return render_template('kontakt.html', current_user=current_user)


@app.route('/user', methods=['GET', 'POST'])
def user():
    if current_user.get_id():
        if request.method == "POST":
            pass
    else:
        flash("Nie jesteś zalogowany!")
        return redirect(url_for("login"))
    return render_template('user.html', current_user=current_user)


@app.route("/kontakt", methods=["POST"])
def receive_data():
    name = request.form["name"]
    email = request.form["email"]
    phone = request.form["phone"]
    message = request.form["message"]
    return f"<h1>{name, message, email, phone}</h1>"


@app.route("/zmien-haslo", methods=["GET", "POST"])
def zmien_haslo():
    global temp_flash
    zmienhaslo = ZmienHaslo()
    if zmienhaslo.validate_on_submit():
        stare_haslo = request.form["stare_haslo"]
        nowe_haslo = request.form["nowe_haslo"]
        powtorz_haslo = request.form["powtorz_haslo"]
        user = User.query.filter_by(id=current_user.get_id()).first()
        if user:
            if not check_password_hash(user.password, stare_haslo):
                flash("Niepoprawne hasło!")
                return redirect(request.url)
            if not nowe_haslo == powtorz_haslo:
                flash("Hasła nie są takie same!")
                return redirect(request.url)
            else:
                new_hash_and_salted_password = generate_password_hash(
                    nowe_haslo,
                    method='pbkdf2:sha256',
                    salt_length=8
                )
                user.password = new_hash_and_salted_password
                db.session.commit()
                temp_flash = "Hasło zostało zmienione!"
                return redirect(url_for("logout"))
    if current_user.get_id():
        return render_template("zmien_haslo.html", form=zmienhaslo, current_user=current_user)
    else:
        flash("Nie jesteś zalogowany!")
        return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if not current_user.get_id():
        login_form = LoginForm()
        if login_form.validate_on_submit():
            email = request.form["email"]
            user = User.query.filter_by(email=email).first()
            password = request.form["password"]
            if user and check_password_hash(user.password, password):
                login_user(user)
                current_user.username = User.query.filter_by(id=current_user.get_id()).first().username
                return redirect(url_for('index'))
            else:
                flash("Niepoprawny e-mail lub hasło.")
                render_template("login.html", form=login_form, current_user=current_user)
        return render_template("login.html", form=login_form, current_user=current_user)
    else:
        flash("Jesteś już zalogowany!")
        return redirect(url_for("index"))


@app.route("/logout")
def logout():
    global temp_flash
    if not current_user.get_id():
        flash("Jesteś już wylogowany!")
        return redirect(url_for("index"))
    else:
        logout_user()
        session.clear()
        if len(temp_flash) > 0:
            flash(f"{temp_flash}")
            temp_flash = ""
        flash(f"Zostałeś wylogowany.", "info")
        return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    registration_form = RegistrationForm()
    if registration_form.validate_on_submit():
        if User.query.filter_by(username=request.form["username"]).first():
            flash(f"Nazwa użytkownika jest zajęta.")
            return redirect(request.url)
        elif User.query.filter_by(email=request.form["email"]).first():
            flash(f"Adres e-mail jest już zajęty.")
            return redirect(request.url)
        elif request.form["password"] != request.form["confirm"]:
            flash(f"Hasła się nie zgadzają!")
            return redirect(request.url)
        elif request.form["accept_tos"] != 'y':
            flash(f"Zaakceptuj warunki")
            return redirect(request.url)
        else:
            hash_and_salted_password = generate_password_hash(
                request.form["password"],
                method='pbkdf2:sha256',
                salt_length=8
            )
            reg_usr = User(
                username=request.form["username"],
                surname=request.form["surname"],
                email=request.form["email"],
                phone=request.form["phone"],
                password=hash_and_salted_password,
                birthdate=request.form["birthdate"],
                accept_tos=request.form["accept_tos"])
            db.session.add(reg_usr)
            db.session.commit()
            flash(f"Rejestracja przebiegła pomyślnie", "info")
            return redirect(url_for("index"))
    else:
        return render_template("register.html", form=registration_form, current_user=current_user)


@app.route('/products/<category>')
def products(category):
    return render_template("products.html", current_user=current_user, all_products=Product.query.all(),
                           category=category)


@app.route('/delete_product/<int:product_id>')
@admin_only
def delete_product(product_id):
    record_to_delete = Product.query.get(product_id)
    db.session.delete(record_to_delete)
    db.session.commit()
    return redirect(url_for('products', category="all"))


@app.route('/koszyk')
def koszyk():
    all_products = []
    prod_dict = {}
    if not current_user.get_id():
        if 'koszyk' in session:
            for x in session['koszyk']:
                if x not in prod_dict:
                    prod_dict[x] = 1
                    all_products.append(Product.query.filter_by(id=x).first())
                else:
                    prod_dict[x] = prod_dict[x] + 1
        else:
            flash('Koszyk jest pusty!')
    else:
        prod_list = []
        for item in Koszyki.query.filter_by(user_id=current_user.get_id()):
            prod_list.append(item.product_id)
        if len(prod_list) > 0:
            for x in prod_list:
                if x not in prod_dict:
                    prod_dict[x] = 1
                    all_products.append(Product.query.filter_by(id=x).first())
                else:
                    prod_dict[x] = prod_dict[x] + 1
        else:
            flash('Koszyk jest pusty!')
    return render_template("koszyk.html", current_user=current_user, all_products=all_products, prod_dict=prod_dict)


@app.route('/dodajdokoszyka/<category>/<int:product_id>')
def dodaj_do_koszyka(category, product_id):
    if not current_user.get_id():
        if 'koszyk' not in session:
            session['koszyk'] = []
        session['koszyk'].append(product_id)
        print(session)
        print(session['koszyk'])
        flash("Dodano produkt do koszyka")
        if category == "kosz":
            return redirect(url_for("koszyk"))
        return redirect(url_for("products", category=category))
    else:
        print(current_user.get_id())
        item_w_koszyku = Koszyki(
            user_id=current_user.get_id(),
            product_id=product_id,
        )
        db.session.add(item_w_koszyku)
        current_user.cart_count = len(Koszyki.query.filter_by(user_id=current_user.get_id()).all())
        db.session.commit()
        flash("Dodano produkt do koszyka")
        if category == "kosz":
            return redirect(url_for("koszyk"))
    return redirect(url_for("products", category=category))


@app.route('/usunzkoszyka/<int:product_id>')
def usun_z_koszyka(product_id):
    if not current_user.get_id():
        if 'koszyk' not in session:
            session['koszyk'] = []
        session['koszyk'].remove(product_id)
        print(session)
        print(session['koszyk'])
        flash("Usunięto produkt z koszyka")
        return redirect(url_for("koszyk"))
    else:
        item_do_usuniecia = Koszyki.query.filter_by(user_id=current_user.get_id(), product_id=product_id).first()
        db.session.delete(item_do_usuniecia)
        current_user.cart_count = len(Koszyki.query.filter_by(user_id=current_user.get_id()).all())
        db.session.commit()
        flash("Usunięto produkt z koszyka")
    return redirect(url_for("koszyk"))


def allowed_image(filename):
    if not "." in filename:
        return False

    ext = filename.rsplit(".", 1)[1]

    if ext.upper() in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        return True
    else:
        return False


def allowed_image_filesize(filesize):
    if int(filesize) < app.config["MAX_IMAGE_FILESIZE"]:
        return True
    else:
        return False


@app.route('/upload-image', methods=['GET', 'POST'])
@admin_only
def upload_image():
    if request.method == "POST":
        if request.files:
            if not allowed_image_filesize(request.cookies.get("filesize")):
                flash(
                    f"Plik jest za duzy. Maksymalna wielkosc to: {app.config['MAX_IMAGE_FILESIZE'] / (1024 * 1024)} MB."
                    f"Wielkość twojego pliku to: {round(int(request.cookies.get('filesize')) / (1024 * 1024), 2)} MB.")
                return redirect(request.url)
            image = request.files["image"]  # name attr w input w html to 'image'
            if image.filename == "":
                flash("Obraz musi miec nazwe!")
                print("Obraz musi miec nazwe!")
                return redirect(request.url)
            if not allowed_image(image.filename):
                flash("To rozszerzenie nie jest dozwolone!")
                print("To rozszerzenie nie jest dozwolone!")
                return redirect(request.url)
            else:
                filename = secure_filename(image.filename)  # werkzeug zwraca "wyczyszczony" i bezpieczny filename
                image.save(os.path.join(app.config["IMAGE_UPLOADS"], filename))
                print(f"{app.config['IMAGE_UPLOADS']}/{filename}")
                flash("Image is saved")
                print("Image is saved")
            return redirect(request.url)
    return render_template("upload_image.html", current_user=current_user)


@app.route('/add-new-product', methods=['GET', 'POST'])
@admin_only
def add_new_product():
    if request.method == "POST":

        img_url = ""

        if request.files:
            if not allowed_image_filesize(request.cookies.get("filesize")):
                flash(
                    f"Plik jest za duzy. Maksymalna wielkosc to: {app.config['MAX_IMAGE_FILESIZE'] / (1024 * 1024)} MB."
                    f"Wielkość twojego pliku to: {round(int(request.cookies.get('filesize')) / (1024 * 1024), 2)} MB.")
                return redirect(request.url)
            image = request.files["image"]  # name attr w input w html to 'image'
            if image.filename == "":
                flash("Nie wybrano obrazu")
            elif image.filename != "" and not allowed_image(image.filename):
                flash("To rozszerzenie nie jest dozwolone!")
                print("To rozszerzenie nie jest dozwolone!")
                return redirect(request.url)
            else:
                filename = secure_filename(image.filename)  # werkzeug zwraca "wyczyszczony" i bezpieczny filename
                image.save(os.path.join(app.config["IMAGE_UPLOADS"], filename))
                img_url = f"/static/img/uploads/{filename}"
                flash("Image is saved")

        new_prod = Product(
            category=request.form["kategoria"],
            product_name=request.form["nazwa"],
            product_description=request.form["opis"],
            img_url=img_url,
            price=request.form["cena"],
            discount_price=request.form["discount"],
            discount_turn_on=request.form["znizka"],
        )

        db.session.add(new_prod)
        db.session.commit()
        flash("Dodano nowy produkt")

        return redirect(url_for("products", category="all"))
    categories = Categories.query.all()
    return render_template("add_new_product.html", current_user=current_user, categories=categories)


@app.route('/edit_the_product/<int:product_id>', methods=['POST', 'GET'])
@admin_only
def edit_the_product(product_id):
    if request.method == 'POST':

        img_url = ""

        if request.files:
            if not allowed_image_filesize(request.cookies.get("filesize")):
                flash(
                    f"Plik jest za duzy. Maksymalna wielkosc to: {app.config['MAX_IMAGE_FILESIZE'] / (1024 * 1024)} MB."
                    f"Wielkość twojego pliku to: {round(int(request.cookies.get('filesize')) / (1024 * 1024), 2)} MB.")
                return redirect(request.url)
            image = request.files["image"]  # name attr w input w html to 'image'
            if image.filename == "":
                flash("Nie wybrano obrazu")
            elif image.filename != "" and not allowed_image(image.filename):
                flash("To rozszerzenie nie jest dozwolone!")
                print("To rozszerzenie nie jest dozwolone!")
                return redirect(request.url)
            else:
                filename = secure_filename(image.filename)  # werkzeug zwraca "wyczyszczony" i bezpieczny filename
                image.save(os.path.join(app.config["IMAGE_UPLOADS"], filename))

                img_url = f"/static/img/uploads/{filename}"
                print(img_url)
                flash("Image is saved")

            product_editing = Product.query.filter_by(id=product_id).first()
            product_editing.category = request.form["kategoria"]
            product_editing.product_name = request.form["nazwa"]
            product_editing.product_description = request.form["opis"]
            if img_url != "":
                product_editing.img_url = img_url
            product_editing.price = request.form["cena"]
            product_editing.discount_price = request.form["discount"]
            product_editing.discount_turn_on = request.form["znizka"]
            flash("Edycja produktu zakończona sukcesem.")
            db.session.commit()
        return redirect(url_for("products", category='all'))
    else:
        product_edited = Product.query.filter_by(id=product_id).first()
        categories = Categories.query.all()
        return render_template("edit-the-product.html", current_user=current_user, product_id=product_id,
                               product_edited=product_edited, categories=categories)


@app.route("/edytuj_dane", methods=["POST", "GET"])
def edytuj_dane():
    user = User.query.filter_by(id=current_user.get_id()).first()
    if request.method == "POST":
        if not len(request.form["email"]) > 6:
            flash("Email jest za krótki")
            return redirect(request.url)
        else:
            if len(request.form["username"]) > 3:
                user.username = request.form["username"]
            if len(request.form["surname"]) > 0:
                user.surname = request.form["surname"]
            user.email = request.form["email"]
            if len(request.form["phone"]) > 7:
                user.phone = request.form["phone"]
            user.birthdate = request.form["birthdate"]
            db.session.commit()
            flash("Dane zostały zmienione")
        return redirect(url_for("user"))
    if user:
        class EdytujDaneForm(FlaskForm):
            username = StringField('Imię', validators=[Length(min=6, max=20)])
            surname = StringField('Nazwisko', validators=[Length(min=6, max=25)])
            email = StringField('Adres e-mail', validators=[Length(min=6, max=50)])
            phone = StringField('Numer telefonu', validators=[Length(max=12)])
            birthdate = DateField('Data urodzenia', format='%Y-%m-%d')
            submit = SubmitField(label="Zatwierdź")
        form = EdytujDaneForm()
        return render_template("edytuj_dane.html", current_user=current_user, user=user, form=form)
    else:
        return redirect(url_for("login"))


@app.route('/roboty-drogowe')
def roboty_drogowe():
    return render_template("roboty-drogowe.html", current_user=current_user)


@app.route('/admin-dashboard')
@admin_only
def admin_dashboard():
    dict_of_users = {}
    for user in User.query.all():
        prod_dict = {}
        if Koszyki.query.filter_by(id=user.id).first():
            prod_list = []
            for item in Koszyki.query.filter_by(user_id=user.id):
                prod_list.append(item.product_id)
            if len(prod_list) > 0:
                for x in prod_list:
                    if x not in prod_dict:
                        prod_dict[x] = 1

                    else:
                        prod_dict[x] = prod_dict[x] + 1
            dict_of_users[user.id] = prod_dict
    for x in dict_of_users:
        print(f" PRINT X: {x}")
        print(f"PRINT DICT_OF_USERS[x]: {dict_of_users[x]}")
        if dict_of_users[x]:
            print(f"IFOWY DICT_OF_USERS[x]: {dict_of_users[x]}")
            for y in dict_of_users[x]:
                print(f"ID ITEMU: {y}")
                print(f"ILOSC ITEMU: {dict_of_users[x][y]}")
    return render_template("admin-dashboard.html", dict_of_users=dict_of_users, all_products=Product.query.all(), all_users=User.query.all(),
                           current_user=current_user, all_messages=Messages.query.all())


@app.route("/lokalizacje")
def lokalizacje():
    return render_template("lokalizacje.html")

if __name__ == "__main__":
    db.create_all()  # tworzy db jesli juz nie istnieje, musi byc przed app.run
    app.run(debug=True)
