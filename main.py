from functools import wraps

import wtforms as wtf
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship, declarative_base, sessionmaker, mapped_column
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms.validators import DataRequired, Length

from forms import CreatePostForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
Base = declarative_base()

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = mapped_column(Integer, primary_key=True)
    blog_owner = db.Column(db.Boolean, nullable=False)
    user_name = db.Column(db.String(250), nullable=False, unique=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="post_author")
    comments = relationship('Comment', back_populates='comment_author')

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = mapped_column(Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = mapped_column(ForeignKey('users.id'))
    post_author = relationship("User", back_populates="posts")


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, nullable=False)
    date = db.Column(db.String(), nullable=False)
    comment_content = db.Column(db.Text(), nullable=False)
    comment_author_id = mapped_column(ForeignKey('users.id'))
    comment_author = relationship("User", back_populates='comments')


class RegistrationForm(FlaskForm):
    user_name = StringField('name', validators=[DataRequired()])
    email = StringField('email', validators=[DataRequired()])
    password = StringField('password', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    user_name = StringField('username', validators=[DataRequired()])
    password = StringField('password', validators=[DataRequired()])
    login = SubmitField("Log in")

class CommentForm(FlaskForm):
    comment_content = CKEditorField("Your comment here:", validators=[DataRequired(), Length(min=3, max=6000)])
    submit = SubmitField("Post Comment")


#User loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

with app.app_context():
    db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    all_comments = {}
    if posts:
        for post in posts:
            post_comments = Comment.query.filter_by(id=post.id).all()
            if post_comments:
                all_comments[post.id] = post_comments
            else:
                all_comments[post.id] = []
    return render_template("index.html", all_posts=posts, all_comments=all_comments)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = request.form['email']
        user_name = request.form['user_name']
        check_email = User.query.filter_by(email=email).first()
        check_user_name = User.query.filter_by(user_name=user_name).first()
        if check_user_name is None and check_email is None:
            password = generate_password_hash(request.form['password'], salt_length=16, method='pbkdf2:sha256')
            new_user = User(email=email, password=password, user_name=user_name, blog_owner=False)
            with app.app_context():
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                flash("Registration successful! Welcome to the blog!")
                return redirect(url_for('get_all_posts'))
        else:
            if check_email:
                flash("This email is already registered. Log in instead!")
            if check_user_name:
                flash("This username is already registered. Log in instead!")
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(user_name=request.form['user_name']).first()
        if user:
            checked_pw = check_password_hash(user.password, request.form['password'])
            if checked_pw:
                login_user(user)
                flash("Logged in! Welcome back!")
                return redirect(url_for('get_all_posts'))
            else:
                flash("Incorrect password.")
                return render_template("login.html", form=form)
        else:
            flash("This username doesn't exist.")
            return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(post_id=post_id).all()
    return render_template("post.html", post=requested_post, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.blog_owner:
            return function(*args, **kwargs)
        else:
            abort(403)
    return wrapper

@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            author=current_user.user_name,
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y, %H:%M:%S")
        )
        with app.app_context():
            db.session.add(new_post)
            db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@admin_only
@app.route("/edit-post/<int:post_id>")
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)

@admin_only
@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route('/<int:post_id>/comment', methods=['GET', 'POST'])
@login_required
def create_comment(post_id):
    if current_user.is_authenticated:
        form = CommentForm()
        if form.validate_on_submit():
            day = date.today().strftime('%B %d, %Y, %H:%M:%S')
            new_comment = Comment(comment_content=form['comment_content'].data, date=day, comment_author_id=current_user.id, post_id=post_id)
            with app.app_context():
                db.session.add(new_comment)
                db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        return render_template('make-comment.html', form=form)
    else:
        flash("You must log in to leave a comment.")
        redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
