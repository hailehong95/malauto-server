from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Optional, Length
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={"placeholder": "admin"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "********"})
    remember_me = BooleanField('Giữ đăng nhập')
    submit = SubmitField("Đăng Nhập")


class CategoryForm(FlaskForm):
    category = SelectField(u'Category', choices=[('unknown', 'Unknown'), ('clean', 'Clean'), ('infected', 'Infected')])
    submit = SubmitField("SUBMIT")


class CommentForm(FlaskForm):
    # content = StringField('Comment', render_kw={"placeholder": "comment.."})
    content = TextAreaField(u'Comment', validators=[Optional(), Length(max=200)])
    submit = SubmitField("COMMENT")
