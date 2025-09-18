from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
# export FLASK_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='r',
                    default='wavatar',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# TODO: Configure Flask-Login
# Configure Flask-Login's Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.get_or_404(User, user_id)
    except:
        pass

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CONFIGURE TABLES
class User(UserMixin, db.Model):  # CREATE TABLE IN DB with the UserMixin
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))
    posts = relationship("BlogPost", back_populates="author")  # relation User - autor posts
    comments = relationship("Comment", back_populates="author")  # relation User - autor comments
    
class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id")) # Create Foreign Key, "users.id"
    author = relationship("User", back_populates="posts")                      # Create reference to the User object
    comments = relationship("Comment", back_populates="parent_post")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id")) # Create Foreign Key, "users.id"
    author = relationship("User", back_populates="comments") 
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_post.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

with app.app_context():
    db.create_all()

def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            i=current_user.id
        except:
            i=0
        if i == 1:
            print("admin ok")
            flash("admin ok")
            return func(*args, **kwargs)
        print("This command is for admin only.")
        flash("This command is for admin only.")
        # return redirect(url_for('get_all_posts'))
        return abort(403)
    return wrapper

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(name = "jmeno1 prijm1", email = "pokus@pokus.xx")
    if form.validate_on_submit():
        name_form=form.name.data
        eml_form=form.email.data
        pwd=form.pwd.data
        try:
            eml_db = db.session.execute(db.select(User).where(User.email==eml_form)).scalar()
        except:
            eml_db=None
        print(f"register search eml: {eml_form} -> {eml_db}")
        if eml_db==None:
            hash = generate_password_hash(pwd, method='pbkdf2:sha256', salt_length=8)
            new_user = User(name=name_form, email=eml_form, password=hash) #, posts=[])
            db.session.add(new_user)
            db.session.commit()
            print(f"new_user added to db: {name_form}")
            flash(f"new_user added to db: {name_form}")
            # Log in and authenticate user after adding details to database.
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
        else:
            print("user enters an email that already exists in the database")
            flash("user enters an email that already exists in the database")
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)

# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    # abort(405)
    form = LoginForm()
    if form.validate_on_submit():
        pwd=form.pwd.data
        email1=form.email.data
        print("search: " + email1)
        try:
            user = db.session.execute(db.select(User).where(User.email==email1)).scalar()
        except:
            user=None
        if user==None:
            print("user not found")
            flash("user not found")
            return redirect(url_for("register", email=email1))
        else:
            print(f"get hash for: {user.name} - {user.email}")
            hash_db=user.password
            if check_password_hash(hash_db, pwd):
                print(f"hash ok")
                login_user(user)
                flash('Logged in successfully.')
                return redirect(url_for('get_all_posts'))
            else:
               print("invalid pwd")
               flash("invalid pwd")
    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You were successfully logged out')
    print('You were successfully logged out')
    return redirect(url_for('get_all_posts'))

@app.route('/')
def get_all_posts():   # home -> get_all_posts
    
    # users = db.session.execute(db.select(User)).scalars()
    # for user in users:
    #     print(f"User: {user.name}")
    #     for comment in user.comments:
    #         print(f"    - Comment: {comment.text}, Belongs to Post: {comment.parent_post.title}")
    # comments = db.session.execute(db.select(Comment)).scalars()
    # for comment in comments:
    #     print(f"Comment: {comment.text}")
    #     print(f"    - User: {comment.author.name}, Belongs to Post: {comment.parent_post.title}")
    # posts = db.session.execute(db.select(BlogPost)).scalars().all()
    # for post in posts:
    #     for comment in post.comments:
    #         print(f"    - Comment: {comment.text}, Belongs to Post: {post.title}")
    
    try:
        posts = db.session.execute(db.select(BlogPost)).scalars().all()
    except:
        posts = []
        flash("db is empty")
    return render_template("index.html", all_posts=posts)

# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("for comment you need login")
            return redirect(url_for("login"))
        new_comment = Comment(
            text=form.comment_text.data,
            author_id=current_user.id,
            post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("post.html", post=requested_post, form=form)

# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            # author=current_user,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)

# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)

# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

if __name__ == "__main__":
    app.run(debug=False, port=5002)
